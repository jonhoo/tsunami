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
//! use tsunami::providers::{Launcher, aws, azure};
//! use rusoto_core::{credential::DefaultCredentialsProvider, Region as AWSRegion};
//! use azure::Region as AzureRegion;
//! fn main() -> Result<(), failure::Error> {
//!     // Initialize AWS
//!     let mut aws = aws::Launcher::default();
//!
//!     // Initialize a TsunamiBuilder for AWS
//!     let mut tb_aws = TsunamiBuilder::default();
//!     tb_aws.use_term_logger();
//!
//!     // Create an AWS machine descriptor and add it to the AWS Tsunami
//!     let m = aws::Setup::default()
//!         .region_with_ubuntu_ami(AWSRegion::UsWest1) // default is UsEast1
//!         .setup(|ssh, _| { // default is a no-op
//!             ssh.command("sudo").arg("apt").arg("update").status()?;
//!             ssh.command("bash").arg("-c")
//!                 .arg("\"curl https://sh.rustup.rs -sSf | sh -- -y\"").status()?;
//!             Ok(())
//!         });
//!     tb_aws.add("aws_vm", m);
//!
//!     // Initialize Azure
//!     let mut azure = azure::Launcher::default();
//!
//!     // Initialize a TsunamiBuilder for Azure
//!     let mut tb_azure = TsunamiBuilder::default();
//!     tb_azure.use_term_logger();
//!     
//!     // Create an Azure machine descriptor and add it to the Azure Tsunami
//!     let m = azure::Setup::default()
//!         .region(AzureRegion::FranceCentral) // default is EastUs
//!         .setup(|ssh, _| { // default is a no-op
//!             ssh.command("sudo").arg("apt").arg("update").status()?;
//!             ssh.command("bash").arg("-c")
//!                 .arg("\"curl https://sh.rustup.rs -sSf | sh -- -y\"").status()?;
//!             Ok(())
//!         });
//!     tb_azure.add("azure_vm", m);
//!
//!     // Launch the VMs
//!     tb_aws.spawn(&mut aws)?;
//!     tb_azure.spawn(&mut azure)?;
//!
//!     // SSH to the VM and run a command on it
//!     let aws_vms = aws.connect_all()?;
//!     let azure_vms = azure.connect_all()?;
//!
//!     let vms = aws_vms.into_iter().chain(azure_vms.into_iter());
//!
//!     // do things with my VMs!
//!     // VMs dropped when aws and azure are dropped.
//!
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
#![warn(unreachable_pub)]
#![warn(missing_docs)]
#![warn(missing_copy_implementations)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unused_extern_crates)]
#![warn(rust_2018_idioms)]
#![warn(missing_debug_implementations)]
#![allow(clippy::type_complexity)]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate slog;

use failure::Error;
use itertools::Itertools;
use std::collections::HashMap;
use std::time;

pub use openssh as ssh;
pub use ssh::Session;

pub mod providers;
use providers::{Launcher, MachineSetup};

/// A handle to an instance currently running as part of a tsunami.
///
/// Run commands on the machine using the [`ssh::Session`] via the `ssh` field.
#[derive(Debug)]
pub struct Machine<'tsunami> {
    /// The friendly name for this machine.
    ///
    /// Corresponds to the name set in [`TsunamiBuilder::add`].
    pub nickname: String,
    /// The public IP address of the machine.
    pub public_ip: String,
    /// The public DNS name of the machine.
    ///
    /// If the instance doesn't have a DNS name, this field will be
    /// equivalent to `public_ip`.
    pub public_dns: String,

    /// If `Some(_)`, an established SSH session to this host.
    pub ssh: Option<ssh::Session>,

    // tie the lifetime of the machine to the Tsunami.
    _tsunami: std::marker::PhantomData<&'tsunami ()>,
}

impl<'t> Machine<'t> {
    fn connect_ssh(
        &mut self,
        log: &slog::Logger,
        username: &str,
        key_path: Option<&std::path::Path>,
        timeout: Option<std::time::Duration>,
    ) -> Result<(), Error> {
        use failure::ResultExt;
        let mut sess = ssh::SessionBuilder::default();

        sess.user(username.to_string()).port(22);

        if let Some(k) = key_path {
            sess.keyfile(k);
        }

        if let Some(t) = timeout {
            sess.connect_timeout(t);
        }

        let sess = sess
            .connect(&self.public_ip)
            .context(format!("failed to ssh to machine {}", self.public_dns))
            .map_err(|e| {
                error!(log, "failed to ssh to {}", self.public_ip);
                e
            })?;

        self.ssh = Some(sess);
        Ok(())
    }
}

/// Use this to prepare and execute a new tsunami.
///
/// Call [`add`](TsunamiBuilder::add) to add machines to the TsunamiBuilder, and
/// [`spawn`](TsunamiBuilder::spawn) to spawn them into the `Launcher`.
///
/// Then, call [`Launcher::connect_all`](providers::Launcher::connect_all) to access the spawned
/// machines.
#[must_use]
#[derive(Debug)]
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
        if self.descriptors.insert(nickname.to_string(), m).is_some() {
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
    ///     let m = tsunami::providers::aws::Setup::default();
    ///     let mut aws: tsunami::providers::aws::Launcher<_> = Default::default();
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
        for (i, m) in std::iter::repeat(m).take(n).enumerate() {
            let name = format!("{}-{}", nickname_prefix, i);
            self.add(&name, m)?;
        }

        Ok(self)
    }

    /// Start up all the hosts.
    ///
    /// This call will block until the instances are spawned into the provided launcher.
    /// SSH connections to each instance are accesssible via
    /// [`connect_all`](providers::Launcher::connect_all).
    ///
    /// # Example
    /// ```rust,no_run
    /// fn main() -> Result<(), failure::Error> {
    ///     use tsunami::providers::Launcher;
    ///     let mut b = tsunami::TsunamiBuilder::default();
    ///     // make a launcher
    ///     let mut aws: tsunami::providers::aws::Launcher<_> = Default::default();
    ///     // spawn hosts into the launcher
    ///     b.add("my_tsunami", Default::default())?.spawn(&mut aws)?;
    ///     // access hosts via the launcher
    ///     let vms = aws.connect_all()?;
    ///     Ok(())
    /// }
    /// ```
    pub fn spawn<L: Launcher<MachineDescriptor = M>>(&self, launcher: &mut L) -> Result<(), Error> {
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
    pub(crate) fn test_logger() -> slog::Logger {
        use slog::Drain;
        let plain = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(plain).build().fuse();
        slog::Logger::root(drain, o!())
    }
}
