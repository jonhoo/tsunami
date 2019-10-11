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
//! use tsunami::providers::{Launcher, aws};
//! use rusoto_core::DefaultCredentialsProvider;
//! fn main() -> Result<(), failure::Error> {
//!     // Initialize AWS
//!     let mut aws: tsunami::providers::aws::AWSLauncher<_> = Default::default();
//!     aws.with_credentials(|| Ok(DefaultCredentialsProvider::new()?));
//!
//!     // Create a machine descriptor and add it to the Tsunami
//!     let mut tb = TsunamiBuilder::default();
//!     let m = aws::MachineSetup::default();
//!     tb.add("my_vm", m);
//!
//!     // Launch the VM
//!     tb.spawn(&mut aws)?;
//!
//!     // SSH to the VM and run a command on it
//!     let vms = aws.connect_all()?;
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
/// Call [`add`](TsunamiBuilder::add) to add machines to the TsunamiBuilder, and
/// [`spawn`](TsunamiBuilder::spawn) to spawn them into the `Launcher`.
///
/// Then, call [`Launcher::connect_all`](providers::Launcher::connect_all) to access the spawned
/// machines.
#[must_use]
pub struct TsunamiBuilder<M: MachineSetup> {
    descriptors: HashMap<String, M>,
    log: slog::Logger,
    max_wait: Option<time::Duration>,
}

impl<M: MachineSetup> Default for TsunamiBuilder<M> {
    fn default() -> Self {
        TsunamiBuilder {
            descriptors: Default::default(),
            log: slog::Logger::root(slog::Discard, o!()),
            max_wait: None,
        }
    }
}

impl<M: MachineSetup> TsunamiBuilder<M> {
    /// Add a machine descriptor to the Tsunami.
    ///
    /// Machine descriptors are specific to the cloud provider they will be used for.
    /// They must be unique for each `TsunamiBuilder`. If `nickname` is a duplicate,
    /// this method will return an `Err` value.
    pub fn add(&mut self, nickname: &str, m: M) -> Result<&mut Self, Error> {
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

    /// Get the logger that `use_term_logger` creates (or was passed to `set_logger`).
    ///
    /// The default logger discards all records passed to it.
    pub fn logger(&self) -> slog::Logger {
        self.log.clone()
    }
}

impl<M: MachineSetup + Clone> TsunamiBuilder<M> {
    /// Add multiple machine descriptors to the Tsunami.
    ///
    /// This is a convenience wrapper around [`add`](TsunamiBuilder::add).
    ///
    /// The `nickname_prefix` is used to name the machines, indexed from 0 to `n`:
    /// ```rust,no_run
    /// fn main() -> Result<(), failure::Error> {
    ///     use tsunami::providers::Launcher;
    ///
    ///     let m = tsunami::providers::aws::MachineSetup::default()
    ///             .region("us-east-1".parse()?)
    ///             .instance_type("t3.medium");
    ///
    ///     let mut aws: tsunami::providers::aws::AWSLauncher<_> = Default::default();
    ///     aws.with_credentials(|| Ok(rusoto_core::DefaultCredentialsProvider::new()?));
    ///
    ///     let mut b = tsunami::TsunamiBuilder::default();
    ///     b.add_multiple(3, "my_tsunami", m)?.spawn(&mut aws)?;
    ///
    ///     let vms = aws.connect_all()?;
    ///     let my_first_vm = vms.get("my_tsunami-0").unwrap();
    ///     let my_last_vm = vms.get("my_tsunami-2").unwrap();
    ///     Ok(())
    /// }
    /// ```
    pub fn add_multiple(
        &mut self,
        n: usize,
        nickname_prefix: &str,
        m: M,
    ) -> Result<&mut Self, Error> {
        (0..n)
            .map(|i| {
                let d = m.clone();
                let name = format!("{}-{}", nickname_prefix, i);

                (name, d)
            })
            .fold(Ok(self), |r, (name, d)| r.and_then(|s| s.add(&name, d)))
    }

    /// Start up all the hosts.
    ///
    /// SSH connections to each instance are accesssible via
    /// [`connect_all`](providers::Launcher::connect_all).
    pub fn spawn<L: Launcher<Machine = M>>(&self, launcher: &mut L) -> Result<(), Error> {
        let descriptors: HashMap<String, M> = self.descriptors.clone();
        let max_wait = self.max_wait;
        let log = self.log.clone();

        info!(log, "spinning up tsunami");

        for (region_name, setups) in descriptors
            .into_iter()
            .map(|(name, setup)| (setup.region(), (name, setup)))
            .into_group_map()
        {
            let region_log = log.new(slog::o!("region" => region_name.clone().to_string()));
            let dsc = providers::LaunchDescriptor {
                region: region_name.clone(),
                log: region_log,
                max_wait,
                machines: setups,
            };

            launcher.launch(dsc)?;
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
