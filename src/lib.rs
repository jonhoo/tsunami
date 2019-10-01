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
extern crate rusoto_core;
extern crate rusoto_ec2;
#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate ssh2;
extern crate tempfile;

use failure::Error;
use itertools::Itertools;
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
    max_wait: Option<time::Duration>,
}

impl<L: Launcher> Default for TsunamiBuilder<L> {
    fn default() -> Self {
        TsunamiBuilder {
            descriptors: Default::default(),
            log: slog::Logger::root(slog::Discard, o!()),
            max_wait: None,
        }
    }
}

impl<L: Launcher> TsunamiBuilder<L> {
    /// Add a machine descriptor to the Tsunami.
    ///
    /// Machine descriptors are specific to the cloud provider they will be used for.
    /// They must be unique for each `TsunamiBuilder`. If `nickname` is a duplicate,
    /// this method will return an `Err` value.
    pub fn add(&mut self, nickname: &str, m: L::Machine) -> Result<&mut Self, Error> {
        if let Some(_) = self.descriptors.insert(nickname.to_string(), m) {
            Err(format_err!("Duplicate machine name {}", nickname))
        } else {
            Ok(self)
        }
    }

    /// Limit how long we should wait for instances to be available before giving up.
    ///
    /// This includes both waiting for spot requests to be satisfied, and for SSH connections to be
    /// established. Defaults to no limit.
    pub fn timeout(&mut self, t: time::Duration) -> &mut Self {
        self.max_wait = Some(t);
        self
    }

    /// Set the logging target for this tsunami.
    ///
    /// By default, logging is disabled (i.e., the default logger is `slog::Discard`).
    pub fn set_logger(&mut self, log: slog::Logger) -> &mut Self {
        self.log = log;
        self
    }

    /// Enable logging to terminal.
    pub fn use_term_logger(&mut self) -> &mut Self {
        use slog::Drain;
        use std::sync::Mutex;

        let decorator = slog_term::TermDecorator::new().build();
        let drain = Mutex::new(slog_term::FullFormat::new(decorator).build()).fuse();
        self.log = slog::Logger::root(drain, o!());

        self
    }

    pub fn logger(&self) -> slog::Logger {
        self.log.clone()
    }

    /// Start up all the hosts.
    ///
    /// SSH connections to each instance are accesssible via
    /// [`connect_all`](providers::Launcher::connect_all).
    pub fn spawn(self, launcher: &mut L) -> Result<(), Error> {
        let Self {
            descriptors,
            max_wait,
            log,
            ..
        } = self;

        info!(log, "spinning up tsunami");

        // 1. group machines into regions
        let mut regions: HashMap<String, providers::LaunchDescriptor<L::Machine>> =
            Default::default();
        for (region_name, setups) in descriptors
            .into_iter()
            .map(|(name, setup)| (setup.region(), (name, setup)))
            .into_group_map()
            .into_iter()
        {
            let region_log = log.new(slog::o!("region" => region_name.clone().to_string()));
            let dsc = providers::LaunchDescriptor {
                region: region_name.clone(),
                log: region_log,
                max_wait,
                machines: setups,
            };

            regions.insert(region_name.to_string(), dsc);
        }

        // 2. launch ze missiles
        for (_, desc) in regions {
            launcher.launch(desc)?;
        }

        Ok(())
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
