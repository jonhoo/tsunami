//! `tsunami` provides an interface for running short-lived jobs and experiments on cloud
//! instances.
//!
//! # Example
//!
//! ```rust,no_run
//! use azure::Region as AzureRegion;
//! use rusoto_core::{credential::DefaultCredentialsProvider, Region as AWSRegion};
//! use tsunami::Tsunami;
//! use tsunami::providers::{aws, azure};
//! #[tokio::main]
//! async fn main() -> Result<(), failure::Error> {
//!     // Initialize AWS
//!     let mut aws = aws::Launcher::default();
//!     // Create an AWS machine descriptor and add it to the AWS Tsunami
//!     aws.spawn(
//!         vec![(
//!             String::from("aws_vm"),
//!             aws::Setup::default()
//!                 .region_with_ubuntu_ami(AWSRegion::UsWest1) // default is UsEast1
//!                 .await
//!                 .unwrap()
//!                 .setup(|ssh, _| {
//!                     // default is a no-op
//!                     Box::pin(async move {
//!                         ssh.command("sudo")
//!                             .arg("apt")
//!                             .arg("update")
//!                             .status()
//!                             .await?;
//!                         ssh.command("bash")
//!                             .arg("-c")
//!                             .arg("\"curl https://sh.rustup.rs -sSf | sh -- -y\"")
//!                             .status()
//!                             .await?;
//!                         Ok(())
//!                     })
//!                 }),
//!         )],
//!         None,
//!         None,
//!     )
//!     .await?;
//!
//!     // Initialize Azure
//!     let mut azure = azure::Launcher::default();
//!     // Create an Azure machine descriptor and add it to the Azure Tsunami
//!     azure
//!         .spawn(
//!             vec![(
//!                 String::from("azure_vm"),
//!                 azure::Setup::default()
//!                     .region(AzureRegion::FranceCentral) // default is EastUs
//!                     .setup(|ssh, _| {
//!                         // default is a no-op
//!                         Box::pin(async move {
//!                             ssh.command("sudo")
//!                                 .arg("apt")
//!                                 .arg("update")
//!                                 .status()
//!                                 .await?;
//!                             ssh.command("bash")
//!                                 .arg("-c")
//!                                 .arg("\"curl https://sh.rustup.rs -sSf | sh -- -y\"")
//!                                 .status()
//!                                 .await?;
//!                             Ok(())
//!                         })
//!                     }),
//!             )],
//!             None,
//!             None,
//!         )
//!         .await?;
//!
//!     // SSH to the VM and run a command on it
//!     let aws_vms = aws.connect_all().await?;
//!     let azure_vms = azure.connect_all().await?;
//!
//!     let vms = aws_vms.into_iter().chain(azure_vms.into_iter());
//!
//!     // do things with my VMs!
//!
//!     // call cleanup() to terminate the instances.
//!     aws.cleanup().await?;
//!     azure.cleanup().await?;
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
extern crate slog;
#[macro_use]
extern crate failure;

use failure::Error;
pub use openssh as ssh;
pub use ssh::Session;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

pub mod providers;

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
    /// The private IP address of the machine, if available.
    pub private_ip: Option<String>,
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
    #[cfg(any(feature = "aws", feature = "azure", feature = "baremetal"))]
    async fn connect_ssh(
        &mut self,
        log: &slog::Logger,
        username: &str,
        key_path: Option<&std::path::Path>,
        timeout: Option<std::time::Duration>,
        port: u16,
    ) -> Result<(), failure::Error> {
        use failure::ResultExt;
        let mut sess = ssh::SessionBuilder::default();

        sess.user(username.to_string()).port(port);

        if let Some(k) = key_path {
            sess.keyfile(k);
        }

        if let Some(t) = timeout {
            sess.connect_timeout(t);
        }

        let sess = sess
            .connect(&self.public_ip)
            .await
            .context(format!("failed to ssh to machine {}", self.public_dns))
            .map_err(|e| {
                slog::error!(log, "failed to ssh to {}", self.public_ip);
                e
            })?;

        self.ssh = Some(sess);
        Ok(())
    }
}

/// Use this trait to launch machines into providers.
///
/// Important: You must call `cleanup` to shut down the instances once you are done. Otherwise, you
/// may incur unexpected charges from the cloud provider.
///
/// This trait is sealed. If you want to implement support for a provider, see [`providers::Launcher`].
pub trait Tsunami: sealed::Sealed {
    /// A type describing a single instance to launch.
    type MachineDescriptor: providers::MachineSetup;

    /// Start up all the hosts.
    ///
    /// The returned future will resolve when the instances are spawned into the provided launcher.
    /// SSH connections to each instance are accesssible via
    /// [`connect_all`](providers::Launcher::connect_all).
    ///
    /// # Arguments
    /// - `descriptors` is an iterator of machine nickname to descriptor. Duplicate nicknames will
    /// cause an error. To add many and auto-generate nicknames, see the helper function
    /// [`crate::make_multiple`].
    /// - `max_wait` limits how long we should wait for instances to be available before giving up.
    /// Passing `None` implies no limit.
    ///
    /// # Example
    /// ```rust,no_run
    /// #[tokio::main]
    /// async fn main() -> Result<(), failure::Error> {
    ///     use tsunami::Tsunami;
    ///     // make a launcher
    ///     let mut aws: tsunami::providers::aws::Launcher<_> = Default::default();
    ///     // spawn a host into the launcher
    ///     aws.spawn(
    ///         vec![(String::from("my_tsunami"), Default::default())],
    ///         None,
    ///         None,
    ///     )
    ///     .await?;
    ///     // access the host via the launcher
    ///     let vms = aws.connect_all().await?;
    ///     // we're done! terminate the instance.
    ///     aws.cleanup().await?;
    ///     Ok(())
    /// }
    /// ```
    fn spawn<'l>(
        &'l mut self,
        descriptors: impl IntoIterator<Item = (String, Self::MachineDescriptor)> + 'static,
        max_wait: Option<std::time::Duration>,
        log: Option<slog::Logger>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + 'l>>;

    /// Return connections to the [`Machine`s](crate::Machine) that `spawn` spawned.
    fn connect_all<'l>(
        &'l self,
    ) -> Pin<Box<dyn Future<Output = Result<HashMap<String, crate::Machine<'l>>, Error>> + 'l>>;

    /// Shut down all instances.
    fn cleanup(self) -> Pin<Box<dyn Future<Output = Result<(), Error>>>>;
}

impl<L: providers::Launcher> Tsunami for L {
    type MachineDescriptor = L::MachineDescriptor;

    fn connect_all<'l>(
        &'l self,
    ) -> Pin<Box<dyn Future<Output = Result<HashMap<String, crate::Machine<'l>>, Error>> + 'l>>
    {
        self.connect_all()
    }

    fn cleanup(self) -> Pin<Box<dyn Future<Output = Result<(), Error>>>> {
        self.cleanup()
    }

    fn spawn<'l>(
        &'l mut self,
        descriptors: impl IntoIterator<Item = (String, Self::MachineDescriptor)> + 'static,
        max_wait: Option<std::time::Duration>,
        log: Option<slog::Logger>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + 'l>> {
        self.spawn(descriptors, max_wait, log)
    }
}

mod sealed {
    pub trait Sealed {}

    impl<T: super::Tsunami> Sealed for T {}
}

/// Get a reasonable default logger.
pub fn get_term_logger() -> slog::Logger {
    use slog::Drain;
    use std::sync::Mutex;

    let decorator = slog_term::TermDecorator::new().build();
    let drain = Mutex::new(slog_term::FullFormat::new(decorator).build()).fuse();
    slog::Logger::root(drain, slog::o!())
}

/// Make multiple machine descriptors.
///
/// The `nickname_prefix` is used to name the machines, indexed from 0 to `n`:
/// ```rust,no_run
/// #[tokio::main]
/// async fn main() -> Result<(), failure::Error> {
///     use tsunami::{
///         get_term_logger, make_multiple,
///         providers::{
///             aws::{self, Setup},
///             Launcher,
///         },
///     };
///     let mut aws: aws::Launcher<_> = Default::default();
///     aws.spawn(
///         make_multiple(3, "my_tsunami", Setup::default()),
///         None,
///         Some(get_term_logger()),
///     )
///     .await?;
///
///     let vms = aws.connect_all().await?;
///     let my_first_vm = vms.get("my_tsunami-0").unwrap();
///     let my_last_vm = vms.get("my_tsunami-2").unwrap();
///     Ok(())
/// }
/// ```
pub fn make_multiple<M: Clone>(n: usize, nickname_prefix: &str, m: M) -> Vec<(String, M)> {
    std::iter::repeat(m)
        .take(n)
        .enumerate()
        .map(|(i, m)| {
            let name = format!("{}-{}", nickname_prefix, i);
            (name, m)
        })
        .collect()
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
