//! `tsunami` provides an interface for running short-lived jobs and experiments on cloud
//! instances.
//!
//! Most interaction with this library happens through
//! [`TsunamiBuilder`](struct.TsunamiBuilder.html) and [`Tsunami`](struct.Tsunami.html).
//!
//! # Example
//!
//! ```rust,no_run
//! use tsunami::TsunamiBuilder;
//! use tsunami::providers::aws;
//! fn main() -> Result<(), failure::Error> {
//!     let mut aws = TsunamiBuilder::<aws::AWSRegion>::default();
//!     let m = aws::MachineSetup::default();
//!     aws.add("my_vm".into(), m);
//!     let tsunami = aws.spawn()?;
//!     let vms = tsunami.get_machines()?;
//!     let my_vm = vms.get("my_vm").unwrap();
//!     let ssh = my_vm.ssh.as_ref().unwrap();
//!     ssh.cmd("hostname").map(|(stdout, _)| println!("{}", stdout))?;
//!     Ok(())
//! }
//! ```
//!
//! # Live-coding
//!
//! An earlier version of this crate was written as part of a live-coding stream series intended for users who
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

use failure::Error;
use itertools::Itertools;
use rayon::prelude::*;
use std::collections::HashMap;
use std::time;

pub use sessh as ssh;
pub use ssh::Session;

pub mod providers;
use providers::{Launcher, MachineSetup};

/// A handle to an instance currently running as part of a tsunami.
///
/// Run commands on the machine using the [`ssh::Session`] via the `ssh` field.
pub struct Machine<'tsunami> {
    pub nickname: String,
    pub public_dns: String,
    pub public_ip: String,

    /// If `Some(_)`, an established SSH session to this host.
    pub ssh: Option<ssh::Session>,

    // tie the lifetime of the machine to the Tsunami.
    _tsunami: std::marker::PhantomData<&'tsunami ()>,
}

/// Use this to prepare and execute a new tsunami.
///
/// Call [`add`](TsunamiBuilder::add) to add machines to the Tsunami, and
/// [`spawn`](TsunamiBuilder::spawn) to spawn them and yield a [`Tsunami`].
/// Then call [`get_machines`](Tsunami::get_machines) to access the machines that were
/// created.
#[must_use]
pub struct TsunamiBuilder<L: Launcher> {
    descriptors: HashMap<String, L::Machine>,
    log: slog::Logger,
    max_duration: Option<time::Duration>,
    max_wait: Option<time::Duration>,
}

impl<L: Launcher> Default for TsunamiBuilder<L> {
    fn default() -> Self {
        TsunamiBuilder {
            descriptors: Default::default(),
            log: slog::Logger::root(slog::Discard, o!()),
            max_duration: None, // 6 hours
            max_wait: None,
        }
    }
}

impl<L: Launcher> TsunamiBuilder<L> {
    /// Add a machine descriptor to the Tsunami.
    ///
    /// Machine descriptors are specific to the cloud provider they will be used for.
    pub fn add(&mut self, nickname: &str, m: L::Machine) {
        self.descriptors.insert(nickname.to_string(), m);
    }

    /// Limit how long we should wait for instances to be available before giving up.
    ///
    /// This includes both waiting for spot requests to be satisfied, and for SSH connections to be
    /// established. Defaults to no limit.
    pub fn wait_limit(&mut self, t: time::Duration) {
        self.max_wait = Some(t);
    }

    /// Set the maxium lifetime of spawned instances, if applicable for the provider.
    ///
    /// EC2 spot instances are normally subject to termination at any point. This library instead
    /// uses [defined duration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-requests.html#fixed-duration-spot-instances)
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

    /// Start up all the hosts.
    ///
    /// Returns a handle, a [Tsunami](Tsunami), from which SSH connections
    /// to each instance are accesssible via [get_machines](Tsunami::get_machines).
    pub fn spawn(self) -> Result<Tsunami<L>, Error> {
        let Self {
            descriptors,
            max_duration,
            max_wait,
            log,
        } = self;

        info!(log, "spinning up tsunami");

        // 1. initialize the set of unique regions to connect to, and group machines into those
        // regions
        let mut regions: HashMap<String, (L, Vec<(String, L::Machine)>)> = Default::default();
        for (region_name, setups) in descriptors
            .into_iter()
            .map(|(name, setup)| (setup.region(), (name, setup)))
            .into_group_map()
            .into_iter()
        {
            let region_log = log.new(slog::o!("region" => region_name.clone().to_string()));
            let prov = L::init(region_log, region_name.clone())?;
            regions.insert(region_name.to_string(), (prov, setups));
        }

        // 2. launch ze missiles
        let providers: Vec<L> = regions
            .into_par_iter()
            .map(|(_, (mut prov, descs))| {
                prov.init_instances(max_duration, max_wait, descs)?;
                Ok(prov)
            })
            .try_fold(Vec::new, |mut provs, res: Result<L, Error>| {
                res.and_then(|prov| {
                    provs.push(prov);
                    Ok(provs)
                })
            })
            .try_reduce(Vec::new, |mut provs, prov| {
                provs.extend(prov);
                Ok(provs)
            })?;

        Ok(Tsunami { providers, log })
    }
}

/// When this is dropped, the instances are all terminated automatically.
///
/// # Note
/// See caveats for Azure and Baremetal machines.
#[must_use]
pub struct Tsunami<L: Launcher> {
    providers: Vec<L>,
    log: slog::Logger,
}

impl<L: Launcher> Tsunami<L> {
    /// Use to access the machines.
    ///
    /// The `HashMap` of machines is keyed by the friendly names
    /// assigned by the call to [add](TsunamiBuilder::add).
    /// The returned `Machine`s will live for the lifetime of self.
    pub fn get_machines<'l>(&'l self) -> Result<HashMap<String, Machine<'l>>, Error> {
        self.providers
            .par_iter()
            .map(|prov| prov.connect_instances())
            .try_fold(
                HashMap::new,
                |mut machs, res: Result<HashMap<String, Machine<'l>>, Error>| {
                    res.and_then(|ms| {
                        machs.extend(ms);
                        Ok(machs)
                    })
                },
            )
            .try_reduce(HashMap::new, |mut machs, ms| {
                machs.extend(ms);
                Ok(machs)
            })
    }

    pub fn logger(&self) -> &slog::Logger {
        &self.log
    }
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
