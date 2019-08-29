//! `tsunami` provides an interface for running short-lived jobs and experiments on EC2 spot block
//! instances. Most interaction with this library happens through
//! [`TsunamiBuilder`](struct.TsunamiBuilder.html).
//!
//! # Live-coding
//!
//! The crate is under development as part of a live-coding stream series intended for users who
//! are already somewhat familiar with Rust, and who want to see something larger and more involved
//! be built. You can find the recordings of past sessions [on
//! YouTube](https://www.youtube.com/playlist?list=PLqbS7AVVErFgY2faCIYjJZv_RluGkTlKt).

#[macro_use]
extern crate failure;
extern crate rand;
extern crate rayon;
extern crate rusoto_core;
extern crate rusoto_ec2;
#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate ssh2;
extern crate tempfile;

use failure::{Error, ResultExt};
use itertools::Itertools;
use rayon::prelude::*;
use std::collections::HashMap;
use std::time;

mod ssh;
pub use ssh::Session;

pub mod providers;
use providers::{Launcher, MachineSetup, Provider, Setup};

/// A handle to an instance currently running as part of a tsunami.
#[derive(Default)]
pub struct Machine {
    pub nickname: String,
    pub public_dns: String,
    pub public_ip: String,

    /// If `Some(_)`, an established SSH session to this host.
    pub ssh: Option<ssh::Session>,
}

/// Use this to prepare and execute a new tsunami.
///
/// availability_zone: Set up the machine in a specific EC2 availability zone.
/// This controls the `availability_zone` field of the
/// [`SpotPlacement`](https://rusoto.github.io/rusoto/rusoto_ec2/struct.SpotPlacement.html)
/// struct (N.B.: even though the documentation claims that the parameter only affects spot
/// fleets, it does appear to affect *all* spot instances).
///
/// A tsunami consists of one or more [`MachineSetup`](struct.MachineSetup.html)s that will be
/// spawned as EC2 spot instances. See
/// [`TsunamiBuilder#add_set`](struct.TsunamiBuilder.html#method.add_set)) for how to construct a
/// tsunami.
#[must_use]
pub struct TsunamiBuilder {
    descriptors: HashMap<String, providers::Setup>,
    log: slog::Logger,
    max_duration: Option<time::Duration>,
    max_wait: Option<time::Duration>,
}

impl Default for TsunamiBuilder {
    fn default() -> Self {
        TsunamiBuilder {
            descriptors: Default::default(),
            log: slog::Logger::root(slog::Discard, o!()),
            max_duration: None, // 6 hours
            max_wait: None,
        }
    }
}

impl TsunamiBuilder {
    pub fn add(&mut self, nickname: String, m: providers::Setup) {
        self.descriptors.insert(nickname, m);
    }

    /// Limit how long we should wait for instances to be available before giving up.
    ///
    /// This includes both waiting for spot requests to be satisfied, and for SSH connections to be
    /// established. Defaults to no limit.
    pub fn wait_limit(&mut self, t: time::Duration) {
        self.max_wait = Some(t);
    }

    /// Set the maxium lifetime of spawned spot instances.
    ///
    /// EC2 spot instances are normally subject to termination at any point. This library instead
    /// uses [defined
    /// duration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-requests.html#fixed-duration-spot-instances)
    /// instances, which cost slightly more, but are never prematurely terminated. The lifetime of
    /// such instances must be declared in advance (1-6 hours), and can be changed with this
    /// method.
    ///
    /// The default duration is 6 hours.
    pub fn set_max_duration(&mut self, hours: u64) {
        self.max_duration = Some(time::Duration::from_secs(hours * 3600));
    }

    /// Set the logging target for this tsunami.
    ///
    /// By default, logging is disabled (i.e., the default logger is `slog::Discard`).
    pub fn set_logger(&mut self, log: slog::Logger) {
        self.log = log;
    }

    /// Enable logging to terminal.
    pub fn use_term_logger(&mut self) {
        use slog::Drain;
        use std::sync::Mutex;

        let decorator = slog_term::TermDecorator::new().build();
        let drain = Mutex::new(slog_term::FullFormat::new(decorator).build()).fuse();
        self.log = slog::Logger::root(drain, o!());
    }

    /// When all instances are up and running, the given closure will be called with a handle to
    /// all spawned hosts. When the closure exits, the instances are all terminated automatically.
    pub fn run<F, R>(self, pause: bool, f: F) -> Result<R, Error>
    where
        F: FnOnce(HashMap<String, Machine>, &slog::Logger) -> Result<R, Error>,
    {
        let TsunamiBuilder {
            descriptors,
            log,
            max_duration,
            max_wait,
        } = self;
        let log = &log;

        let expected_num: u32 = descriptors.len() as u32;

        // 1. initialize the set of unique regions to connect to, and group machines into those
        // regions
        let regions = descriptors
            .into_iter()
            .map(|(name, setup)| (setup.region(), (name, setup)))
            .into_group_map()
            .into_iter()
            .map(|(region_name, setups)| {
                let region_log = log.new(slog::o!("region" => region_name.clone()));
                let prov = setups[0].1.init_provider(region_log)?;
                Ok((region_name, (prov, setups)))
            })
            .collect::<Result<HashMap<String, (Provider, Vec<(String, Setup)>)>, Error>>()?;

        info!(log, "spinning up tsunami");

        // 2. launch ze missiles
        let (providers, machines): (Vec<Provider>, HashMap<String, Machine>) = regions
            .into_par_iter()
            .map(|(_, (mut prov, machines))| {
                let instances = prov.init_instances(max_duration, max_wait, machines)?;
                Ok((prov, instances))
            })
            .try_fold(
                || (Vec::new(), HashMap::default()),
                |(mut provs, mut machs),
                 res: Result<(Provider, HashMap<String, Machine>), Error>| {
                    res.and_then(|(prov, ms)| {
                        provs.push(prov);
                        machs.extend(ms);
                        Ok((provs, machs))
                    })
                },
            )
            .try_reduce(
                || (Vec::new(), HashMap::default()),
                |(mut provs, mut machs), (prov, ms)| {
                    provs.extend(prov);
                    machs.extend(ms);
                    Ok((provs, machs))
                },
            )?;

        let mut res = None;
        let running = machines.len() as u32;
        if running == expected_num {
            // 3. invoke F with Machine descriptors
            let start = time::Instant::now();
            info!(log, "quiet before the storm");
            res = Some(
                f(machines, log)
                    .context("tsunami main routine failed")
                    .map_err(|e| {
                        crit!(log, "main tsunami routine failed");
                        println!("{}", e);
                        wait_for_continue(log);
                        e
                    })?,
            );
            info!(log, "the power of the tsunami was unleashed"; "duration" => start.elapsed().as_secs());
        } else {
            crit!(
                log,
                "only {} out of {} machines were started; aborting",
                running,
                expected_num
            );
        }

        debug!(log, "all done");
        if pause {
            wait_for_continue(log);
        }

        drop(providers);
        res.ok_or_else(|| format_err!("no result from main()"))
    }
}

fn wait_for_continue(log: &slog::Logger) {
    debug!(
        log,
        "pausing for manual instance inspection, press enter to continue"
    );

    use std::io::prelude::*;
    let stdin = std::io::stdin();
    let mut iterator = stdin.lock().lines();
    iterator.next().unwrap().unwrap();
}

#[cfg(test)]
mod test {
    pub fn test_logger() -> slog::Logger {
        use slog::Drain;
        let plain = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(plain).build().fuse();
        slog::Logger::root(drain, o!())
    }
}
