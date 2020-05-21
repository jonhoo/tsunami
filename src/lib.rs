//! `tsunami` provides an interface for running one-off jobs on cloud instances.
//!
//! **This crate requires nightly Rust.**
//!
//! Imagine you need to run an experiment that involves four machines of different types on AWS. Or
//! on Azure. And each one needs to be set up in a particular way. Maybe one is a server, two are
//! load generating clients, and one is a monitor of some sort. You want to spin them all up with a
//! custom AMI, in different regions, and then run some benchmarks once they're all up and running.
//!
//! This crate makes that trivial.
//!
//! You say what machines you want, and the library takes care of the rest. It uses the cloud
//! service's API to start the machines as appropriate, and gives you [ssh connections] to each
//! host as it becomes available to run setup. When all the machines are available, you can connect
//! to them all in a single step, and then run your distributed job. When you're done, `tsunami`
//! tears everything down for you. And did I mention it even supports AWS spot instances, so it
//! even saves you money?
//!
//! How does this magic work? Take a look at this example:
//!
//! ```rust,no_run
//! use azure::Region as AzureRegion;
//! use rusoto_core::{credential::DefaultCredentialsProvider, Region as AWSRegion};
//! use tsunami::Tsunami;
//! use tsunami::providers::{aws, azure};
//! #[tokio::main]
//! async fn main() -> Result<(), color_eyre::Report> {
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
//!                 .setup(|ssh| {
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
//!                     .setup(|ssh| {
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
//!         )
//!         .await?;
//!
//!     // SSH to the VMs and run commands on it
//!     let aws_vms = aws.connect_all().await?;
//!     let azure_vms = azure.connect_all().await?;
//!
//!     let vms = aws_vms.into_iter().chain(azure_vms.into_iter());
//!
//!     // do amazing things with the VMs!
//!     // you have access to things like ip addresses for each host too.
//!
//!     // call terminate_all() to terminate the instances.
//!     aws.terminate_all().await?;
//!     azure.terminate_all().await?;
//!     Ok(())
//! }
//! ```
//!
//! # Where are the logs?
//!
//! This crate uses [`tracing`](https://docs.rs/tracing), which does not log anything by default,
//! since the crate allows you to [plug and
//! play](https://docs.rs/tracing/0.1.14/tracing/#in-executables) which "consumer" you want for
//! your trace points. If you want logging that "just works", you'll want
//! [`tracing_subscriber::fmt`](https://docs.rs/tracing-subscriber/0.2/tracing_subscriber/fmt/index.html),
//! which you can instantiate (after adding it to your Cargo.toml) with:
//!
//! ```rust,ignore
//! tracing_subscriber::fmt::init();
//! ```
//!
//! And then run your application with, for example, `RUST_LOG=info` to get logs. If you're using
//! the `log` crate, you can instead just add a dependency on `tracing` with the `log` feature
//! enabled, and things should just "magically" work.
//!
//! If you also want better tracing of errors (which I think you do), take a look at the
//! documentation for [`color-eyre`](https://docs.rs/color_eyre/), which includes an example for
//! how to set up `tracing` with [`tracing-error`](https://docs.rs/tracing-error).
//!
//! # Live-coding
//!
//! An earlier version of this crate was written as part of a live-coding stream series intended
//! for users who are already somewhat familiar with Rust, and who want to see something larger and
//! more involved be built. You can find the recordings of past sessions [on
//! YouTube](https://www.youtube.com/playlist?list=PLqbS7AVVErFgY2faCIYjJZv_RluGkTlKt).

#![warn(
    unreachable_pub,
    missing_docs,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    rust_2018_idioms,
    missing_debug_implementations
)]
#![allow(clippy::type_complexity)]

use color_eyre::Report;
pub use openssh as ssh;
pub use ssh::Session;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use tracing::instrument;

pub mod providers;

#[derive(Debug)]
struct MachineDescriptor<'tsunami> {
    pub(crate) nickname: String,
    pub(crate) public_ip: String,
    pub(crate) private_ip: Option<String>,
    pub(crate) public_dns: String,

    // tie the lifetime of the machine to the Tsunami.
    _tsunami: std::marker::PhantomData<&'tsunami ()>,
}
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

    /// An established SSH session to this host.
    pub ssh: ssh::Session,

    // tie the lifetime of the machine to the Tsunami.
    _tsunami: std::marker::PhantomData<&'tsunami ()>,
}

impl<'t> MachineDescriptor<'t> {
    #[cfg(any(feature = "aws", feature = "azure", feature = "baremetal"))]
    #[instrument(level = "debug", skip(key_path, timeout))]
    async fn connect_ssh(
        self,
        username: &str,
        key_path: Option<&std::path::Path>,
        timeout: Option<std::time::Duration>,
        port: u16,
    ) -> Result<Machine<'t>, Report> {
        let mut sess = ssh::SessionBuilder::default();

        sess.user(username.to_string()).port(port);

        if let Some(k) = key_path {
            sess.keyfile(k);
        }

        if let Some(t) = timeout {
            sess.connect_timeout(t);
        }

        tracing::trace!("connecting");
        let sess = sess.connect(&self.public_ip).await?;
        tracing::trace!("connected");

        Ok(Machine {
            nickname: self.nickname,
            public_ip: self.public_ip,
            private_ip: self.private_ip,
            public_dns: self.public_dns,
            _tsunami: self._tsunami,

            ssh: sess,
        })
    }
}

/// Use this trait to launch machines into providers.
///
/// Important: You must call `terminate_all` to shut down the instances once you are done. Otherwise, you
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
    /// The argument `descriptors` is an iterator of machine nickname to descriptor. Duplicate
    /// nicknames will cause an error. To add many and auto-generate nicknames, see the helper
    /// function [`crate::make_multiple`].
    ///
    /// `max_wait` limits how long we should wait for instances to be available before giving up.
    /// Passing `None` implies no limit.
    ///
    /// # Example
    /// ```rust,no_run
    /// #[tokio::main]
    /// async fn main() -> Result<(), color_eyre::Report> {
    ///     use tsunami::Tsunami;
    ///     // make a launcher
    ///     let mut aws: tsunami::providers::aws::Launcher<_> = Default::default();
    ///     // spawn a host into the launcher
    ///     aws.spawn(vec![(String::from("my_tsunami"), Default::default())], None).await?;
    ///     // access the host via the launcher
    ///     let vms = aws.connect_all().await?;
    ///     // we're done! terminate the instance.
    ///     aws.terminate_all().await?;
    ///     Ok(())
    /// }
    /// ```
    fn spawn<'l, I>(
        &'l mut self,
        descriptors: I,
        max_wait: Option<std::time::Duration>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'l>>
    where
        I: IntoIterator<Item = (String, Self::MachineDescriptor)> + Send + 'static,
        I: std::fmt::Debug,
        I::IntoIter: Send;

    /// Return connections to the [`Machine`s](crate::Machine) that `spawn` spawned.
    fn connect_all<'l>(
        &'l self,
    ) -> Pin<
        Box<dyn Future<Output = Result<HashMap<String, crate::Machine<'l>>, Report>> + Send + 'l>,
    >;

    /// Shut down all instances.
    fn terminate_all(self) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send>>;
}

impl<L: providers::Launcher> Tsunami for L {
    type MachineDescriptor = L::MachineDescriptor;

    fn connect_all<'l>(
        &'l self,
    ) -> Pin<
        Box<dyn Future<Output = Result<HashMap<String, crate::Machine<'l>>, Report>> + Send + 'l>,
    > {
        self.connect_all()
    }

    fn terminate_all(self) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send>> {
        self.terminate_all()
    }

    fn spawn<'l, I>(
        &'l mut self,
        descriptors: I,
        max_wait: Option<std::time::Duration>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'l>>
    where
        I: IntoIterator<Item = (String, Self::MachineDescriptor)> + Send + 'static,
        I: std::fmt::Debug,
        I::IntoIter: Send,
    {
        self.spawn(descriptors, max_wait)
    }
}

mod sealed {
    pub trait Sealed {}

    impl<L: crate::providers::Launcher> Sealed for L {}
}

/// Make multiple machine descriptors.
///
/// The `nickname_prefix` is used to name the machines, indexed from 0 to `n`:
/// ```rust,no_run
/// #[tokio::main]
/// async fn main() -> Result<(), color_eyre::Report> {
///     use tsunami::{
///         Tsunami,
///         make_multiple,
///         providers::aws::{self, Setup},
///     };
///     let mut aws: aws::Launcher<_> = Default::default();
///     aws.spawn(make_multiple(3, "my_tsunami", Setup::default()), None).await?;
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
