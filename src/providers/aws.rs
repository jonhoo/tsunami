//! AWS backend for tsunami.
//!
//! The primary `impl Launcher` type is [`Launcher`].
//! It internally uses the lower-level, region-specific [`aws::RegionLauncher`].
//! Both these types use [`aws::Setup`] as their descriptor type.
//!
//! By default, this implementation uses 6-hour [defined
//! duration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-requests.html#fixed-duration-spot-instances)
//! spot instances. You can switch to on-demand instances using [`Launcher::set_mode`].
//!
//! # Examples
//! ```rust,no_run
//! #[tokio::main]
//! async fn main() {
//!     use tsunami::Tsunami;
//!     use tsunami::providers::aws;
//!
//!     let mut l = aws::Launcher::default();
//!     // make the defined-duration instances expire after 1 hour
//!     l.set_mode(aws::LaunchMode::duration_spot(1));
//!     l.spawn(vec![(String::from("my machine"), aws::Setup::default())], None).await.unwrap();
//!     let vms = l.connect_all().await.unwrap();
//!     let my_machine = vms.get("my machine").unwrap();
//!     let out = my_machine
//!         .ssh
//!         .command("echo")
//!         .arg("\"Hello, EC2\"")
//!         .output()
//!         .await
//!         .unwrap();
//!     let stdout = std::string::String::from_utf8(out.stdout).unwrap();
//!     println!("{}", stdout);
//!     l.terminate_all().await.unwrap();
//! }
//! ```
//! ```rust,no_run
//! use rusoto_core::{credential::DefaultCredentialsProvider};
//! use tsunami::Tsunami;
//! use tsunami::providers::aws::{self, Region};
//! #[tokio::main]
//! async fn main() -> Result<(), color_eyre::Report> {
//!     // Initialize AWS
//!     let mut aws = aws::Launcher::default();
//!     // make the defined-duration instances expire after 1 hour
//!     // default is the maximum (6 hours)
//!     aws.set_mode(aws::LaunchMode::duration_spot(1)).open_ports();
//!
//!     // Create a machine descriptor and add it to the Tsunami
//!     let m = aws::Setup::default()
//!         .region_with_ubuntu_ami(Region::UsWest1) // default is UsEast1
//!         .await
//!         .unwrap()
//!         .setup(|vm| {
//!             // default is a no-op
//!             Box::pin(async move {
//!                 vm.ssh.command("sudo")
//!                     .arg("apt")
//!                     .arg("update")
//!                     .status()
//!                     .await?;
//!                 vm.ssh.command("bash")
//!                     .arg("-c")
//!                     .arg("\"curl https://sh.rustup.rs -sSf | sh -- -y\"")
//!                     .status()
//!                     .await?;
//!                 Ok(())
//!             })
//!         });
//!
//!     // Launch the VM
//!     aws.spawn(vec![(String::from("my_vm"), m)], None).await?;
//!
//!     // SSH to the VM and run a command on it
//!     let vms = aws.connect_all().await?;
//!     let my_vm = vms.get("my_vm").unwrap();
//!     println!("public ip: {}", my_vm.public_ip);
//!     my_vm.ssh
//!         .command("git")
//!         .arg("clone")
//!         .arg("https://github.com/jonhoo/tsunami")
//!         .status()
//!         .await?;
//!     my_vm.ssh
//!         .command("bash")
//!         .arg("-c")
//!         .arg("\"cd tsunami && cargo build\"")
//!         .status()
//!         .await?;
//!     aws.terminate_all().await?;
//!     Ok(())
//! }
//! ```

use color_eyre::{
    eyre::{self, eyre, WrapErr},
    Report,
};
use educe::Educe;
use itertools::Itertools;
use rusoto_core::credential::{DefaultCredentialsProvider, ProvideAwsCredentials};
use rusoto_core::request::HttpClient;
pub use rusoto_core::Region;
use rusoto_ec2::Ec2;
use std::collections::HashMap;
use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
use std::time;
use tracing::instrument;
use tracing_futures::Instrument;

/// Dictate how a set of instances should be launched.
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)]
#[non_exhaustive]
pub enum LaunchMode {
    /// Use AWS [defined duration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-requests.html#fixed-duration-spot-instances)
    /// spot instances. Fails with an error if there is no spot capacity.
    DefinedDuration {
        /// The lifetime of the defined duration instances.
        /// This value must be between 1 and 6 hours.
        hours: usize,
    },
    /// Try to use AWS [defined duration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-requests.html#fixed-duration-spot-instances)
    /// spot instances. If that fails, e.g. due to lack of capacity, use `OnDemand` instead.
    TrySpot {
        /// The lifetime of the defined duration instances.
        /// This value must be between 1 and 6 hours.
        hours: usize,
    },
    /// Use regular AWS on-demand instances.
    OnDemand,
}

impl LaunchMode {
    /// Launch using AWS [defined duration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-requests.html#fixed-duration-spot-instances) spot instances.
    ///
    /// The lifetime of such instances must be declared in advance (1-6 hours).
    /// This method thus clamps `hours` to be between 1 and 6.
    pub fn duration_spot(hours: usize) -> Self {
        let hours = std::cmp::min(hours, 6);
        let hours = std::cmp::max(hours, 1);
        Self::DefinedDuration { hours }
    }

    /// Launch using regular AWS on-demand instances.
    pub fn on_demand() -> Self {
        Self::OnDemand
    }
}

/// Available configurations of availability zone specifiers.
///
/// See [the aws docs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#using-regions-availability-zones-launching) for more information.
#[derive(Debug, Clone)]
pub enum AvailabilityZoneSpec {
    /// `Any` (the default) will place the instance anywhere there is capacity.
    Any,
    /// `Cluster` will group instances by the given `usize` id, and ensure that each group is
    /// placed in the same availability zone. To specify exactly which availability zone the
    /// machines should be placed in, see `AvailabilityZoneSpec::Specify`.
    Cluster(usize),
    /// `Specify` will place all the instances in the named availability zone.
    ///
    /// The string should give the full name of the availability zone, such as `us-east-1a`.
    Specify(String),
}

impl Default for AvailabilityZoneSpec {
    fn default() -> Self {
        Self::Any
    }
}

impl std::fmt::Display for AvailabilityZoneSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            AvailabilityZoneSpec::Any => write!(f, "any"),
            AvailabilityZoneSpec::Cluster(ref i) => write!(f, "cluster({})", i),
            AvailabilityZoneSpec::Specify(ref s) => write!(f, "{}", s),
        }
    }
}

/// A descriptor for a particular machine setup in a tsunami.
///
/// The default region and ami is Ubuntu 18.04 LTS in us-east-1. The default AMI is updated on a
/// passive basis, so you almost certainly want to call one of:
/// - [`Setup::region_with_ubuntu_ami`]
/// - [`Setup::ami`]
/// - [`Setup::region`]
/// to change these defaults.
#[derive(Clone, Educe)]
#[educe(Debug)]
pub struct Setup {
    region: Region,
    availability_zone: AvailabilityZoneSpec,
    instance_type: String,
    ami: String,
    username: String,
    #[educe(Debug(ignore))]
    setup_fn: Option<
        Arc<
            dyn for<'r> Fn(
                    &'r crate::Machine<'_>,
                )
                    -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'r>>
                + Send
                + Sync
                + 'static,
        >,
    >,
}

impl super::MachineSetup for Setup {
    type Region = String;

    fn region(&self) -> Self::Region {
        match self.availability_zone {
            AvailabilityZoneSpec::Specify(ref id) => format!("{}-{}", self.region.name(), id),
            AvailabilityZoneSpec::Cluster(id) => format!("{}-{}", self.region.name(), id),
            AvailabilityZoneSpec::Any => self.region.name().to_string(),
        }
    }
}

impl Default for Setup {
    fn default() -> Self {
        Setup {
            region: Region::UsEast1,
            availability_zone: AvailabilityZoneSpec::Any,
            instance_type: "t3.small".into(),
            ami: String::from("ami-085925f297f89fce1"),
            username: "ubuntu".into(),
            setup_fn: None,
        }
    }
}

impl Setup {
    /// Set up the machine in a specific EC2
    /// [`Region`](http://rusoto.github.io/rusoto/rusoto_core/region/enum.Region.html).
    ///
    /// The default region is us-east-1. [Available regions are listed
    /// here.](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions)
    ///
    /// AMIs are region-specific.  This method uses
    /// [`ubuntu-ami`](https://crates.io/crates/ubuntu-ami), which queries [Ubuntu's cloud image
    /// list](https://cloud-images.ubuntu.com/) to get the latest Ubuntu 18.04 LTS AMI in the
    /// selected region.
    pub async fn region_with_ubuntu_ami(mut self, region: Region) -> Result<Self, Report> {
        self.region = region.clone();
        let ami: String = UbuntuAmi::new(region).await?.into();
        Ok(self.ami(ami, "ubuntu"))
    }

    /// Set the username used to ssh into the machine.
    ///
    /// If the user sets a custom AMI, they must call this method to
    /// set a username.
    pub fn username(self, username: impl ToString) -> Self {
        Self {
            username: username.to_string(),
            ..self
        }
    }

    /// The new instance will start out in the state dictated by the Amazon Machine Image specified
    /// in `ami`. Default is Ubuntu 18.04 LTS.
    pub fn ami(self, ami: impl ToString, username: impl ToString) -> Self {
        Self {
            ami: ami.to_string(),
            username: username.to_string(),
            ..self
        }
    }

    /// The given AWS EC2 instance type will be used.
    ///
    /// Note that only [EC2 Defined Duration Spot
    /// Instance types](https://aws.amazon.com/ec2/spot/pricing/) are allowed.
    pub fn instance_type(mut self, typ: impl ToString) -> Self {
        self.instance_type = typ.to_string();
        self
    }

    /// Specify instance setup.
    ///
    /// The provided callback, `setup`, is called once
    /// for every spawned instances of this type with a handle
    /// to the target machine. Use [`Machine::ssh`] to issue
    /// commands on the host in question.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tsunami::providers::aws::Setup;
    ///
    /// let m = Setup::default().setup(|vm| {
    ///     Box::pin(async move {
    ///         vm.ssh
    ///             .command("sudo")
    ///             .arg("apt")
    ///             .arg("update")
    ///             .status()
    ///             .await?;
    ///         Ok(())
    ///     })
    /// });
    /// ```
    pub fn setup(
        mut self,
        setup: impl for<'r> Fn(
                &'r crate::Machine<'_>,
            ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'r>>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.setup_fn = Some(Arc::new(setup));
        self
    }

    /// Set up the machine in a specific EC2
    /// [`Region`](http://rusoto.github.io/rusoto/rusoto_core/region/enum.Region.html).
    ///
    /// The default region is us-east-1. [Available regions are listed
    /// here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions)
    ///
    /// AMIs are region-specific. Therefore, when changing the region a new ami must be given, with
    /// a corresponding username. For a shortcut helper function that provides an Ubunti ami, see
    /// `region_with_ubuntu_ami`.
    pub fn region(mut self, region: Region, ami: impl ToString, username: impl ToString) -> Self {
        self.region = region;
        self.ami(ami, username)
    }

    /// Set up the machine in a specific EC2 availability zone.
    ///
    /// The default availability zone is unspecified - EC2 will launch the machine wherever there
    /// is capacity.
    pub fn availability_zone(self, az: AvailabilityZoneSpec) -> Self {
        Self {
            availability_zone: az,
            ..self
        }
    }
}

/// AWS EC2 spot instance launcher.
///
/// This is a lower-level API. Most users will use [`crate::TsunamiBuilder::spawn`].
///
/// Each individual region is handled by `RegionLauncher`.
///
/// While the regions are initialized serially, the setup functions for each machine are executed
/// in parallel (within each region).
///
/// By default, `Launcher` launches instances using 6-hour [defined
/// duration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-requests.html#fixed-duration-spot-instances)
/// spot requests.
#[derive(Educe)]
#[educe(Debug)]
pub struct Launcher<P = DefaultCredentialsProvider> {
    #[educe(Debug(ignore))]
    credential_provider: Box<dyn Fn() -> Result<P, Report> + Send + Sync>,
    mode: LaunchMode,
    use_open_ports: bool,
    regions: HashMap<<Setup as super::MachineSetup>::Region, RegionLauncher>,
}

impl Default for Launcher {
    fn default() -> Self {
        Launcher {
            credential_provider: Box::new(|| Ok(DefaultCredentialsProvider::new()?)),
            mode: LaunchMode::DefinedDuration { hours: 6 },
            use_open_ports: false,
            regions: Default::default(),
        }
    }
}

impl<P> Launcher<P> {
    /// Set defined duration instance max instance duration.
    ///
    /// The lifetime of such instances must be declared in advance (1-6 hours).
    /// This method thus clamps `t` to be between 1 and 6.
    ///
    /// By default, we use 6 hours (the maximum).
    ///
    /// This method also changes the mode to [`LaunchMode::DefinedDuration`].
    #[deprecated(note = "prefer set_mode")]
    pub fn set_max_instance_duration(&mut self, t: usize) -> &mut Self {
        self.mode = LaunchMode::duration_spot(t);
        self
    }

    /// Set the launch mode to use for future instances.
    ///
    /// See [`LaunchMode`] for more details.
    pub fn set_mode(&mut self, mode: LaunchMode) -> &mut Self {
        self.mode = mode;
        self
    }

    /// The machines spawned on this launcher will have
    /// ports open to the public Internet.
    pub fn open_ports(&mut self) -> &mut Self {
        self.use_open_ports = true;
        self
    }

    /// Set the credential provider used to authenticate to EC2.
    ///
    /// The provided function is called once for each region, and is expected to produce a
    /// [`P: ProvideAwsCredentials`](https://docs.rs/rusoto_core/0.40.0/rusoto_core/trait.ProvideAwsCredentials.html)
    /// that gives access to the region in question.
    pub fn with_credentials<P2>(
        self,
        f: impl Fn() -> Result<P2, Report> + Send + Sync + 'static,
    ) -> Launcher<P2> {
        Launcher {
            credential_provider: Box::new(f),
            mode: self.mode,
            use_open_ports: self.use_open_ports,
            regions: self.regions,
        }
    }
}

impl<P> super::Launcher for Launcher<P>
where
    P: ProvideAwsCredentials + Send + Sync + 'static,
{
    type MachineDescriptor = Setup;

    #[instrument(level = "debug", skip(self))]
    fn launch<'l>(
        &'l mut self,
        l: super::LaunchDescriptor<Self::MachineDescriptor>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'l>> {
        Box::pin(async move {
            let prov = (*self.credential_provider)()?;
            let Self {
                use_open_ports,
                mode,
                ref mut regions,
                ..
            } = self;

            if !regions.contains_key(&l.region) {
                let region_span = tracing::debug_span!("new_region", name = %l.region, az = %l.machines[0].1.availability_zone);
                let awsregion = RegionLauncher::new(
                    // region name and availability_zone spec are guaranteed to be the same because
                    // they are included in the region specifier.
                    l.machines[0].1.region.name(),
                    l.machines[0].1.availability_zone.clone(),
                    prov,
                    *use_open_ports,
                )
                .instrument(region_span)
                .await?;
                regions.insert(l.region.clone(), awsregion);
            }

            let region_span = tracing::debug_span!("region", name = %l.region);
            regions
                .get_mut(&l.region)
                .unwrap()
                .launch(mode.clone(), l.max_wait, l.machines)
                .instrument(region_span)
                .await?;
            Ok(())
        }.in_current_span())
    }

    #[instrument(level = "debug", skip(self, max_wait))]
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
        use super::MachineSetup;
        Box::pin(
            async move {
                tracing::info!("spinning up tsunami");

                // group by region
                let names_to_setups = descriptors
                    .into_iter()
                    .map(|(name, setup)| (MachineSetup::region(&setup), (name, setup)))
                    .into_group_map();

                // separate into two lists:
                // 1. we already have a RegionLauncher
                // 2. we don't
                let (mut haves, have_nots): (Vec<_>, Vec<_>) = names_to_setups
                    .into_iter()
                    .partition(|(region_name, _)| self.regions.contains_key(region_name));

                // check that this works before unwrap() below
                let _prov = (*self.credential_provider)()?;
                let use_open_ports = self.use_open_ports;

                let newly_initialized: Vec<Result<_, _>> =
                    futures_util::future::join_all(have_nots.iter().map(|(region_name, s)| {
                        let region_span = tracing::debug_span!("new_region", region = %region_name);
                        let prov = (*self.credential_provider)().unwrap();
                        async move {
                            let awsregion = RegionLauncher::new(
                                // region name and availability_zone spec are guaranteed to be the
                                // same because they are included in the region specifier.
                                s[0].1.region.name(),
                                s[0].1.availability_zone.clone(),
                                prov,
                                use_open_ports,
                            )
                            .await?;
                            Ok::<_, Report>((region_name.clone(), awsregion))
                        }
                        .instrument(region_span)
                    }))
                    .await;
                self.regions.extend(
                    newly_initialized
                        .into_iter()
                        .collect::<Result<Vec<_>, _>>()?,
                );

                // the have-nots are now haves
                haves.extend(have_nots);

                // Launch instances in the regions concurrently.
                //
                // The borrow checker can't know that each future only accesses one entry of the
                // hashmap - for its RegionLauncher (guaranteed by the `into_group_map()` above).
                // So, we help it by taking the appropriate RegionLauncher out of the hashmap,
                // running `launch()`, then putting everything back later.
                let max_wait = max_wait;
                let regions = futures_util::future::join_all(haves.into_iter().map(
                    |(region_name, machines)| {
                        // unwrap ok because everything is a have now
                        let mut region_launcher = self.regions.remove(&region_name).unwrap();
                        let region_span = tracing::debug_span!("region", region = %region_name);
                        let mode = self.mode.clone();
                        async move {
                            if let Err(e) = region_launcher.launch(mode, max_wait, machines).await {
                                Err((region_name, region_launcher, e))
                            } else {
                                Ok((region_name, region_launcher))
                            }
                        }
                        .instrument(region_span)
                    },
                ))
                .await;

                // Put our stuff back where we found it.
                let (regions, res) =
                    regions
                        .into_iter()
                        .fold((vec![], None), |acc, r| match (acc, r) {
                            ((mut rs, x), Ok((name, rl))) => {
                                rs.push((name, rl));
                                (rs, x)
                            }
                            ((mut rs, None), Err((name, rl, e))) => {
                                rs.push((name, rl));
                                (rs, Some(e))
                            }
                            ((mut rs, x @ Some(_)), Err((name, rl, _))) => {
                                rs.push((name, rl));
                                (rs, x)
                            }
                        });
                self.regions.extend(regions.into_iter());

                if let Some(e) = res {
                    Err(e)
                } else {
                    Ok(())
                }
            }
            .in_current_span(),
        )
    }

    #[instrument(level = "debug")]
    fn connect_all<'l>(
        &'l self,
    ) -> Pin<
        Box<dyn Future<Output = Result<HashMap<String, crate::Machine<'l>>, Report>> + Send + 'l>,
    > {
        Box::pin(async move { collect!(self.regions) }.in_current_span())
    }

    #[instrument(level = "debug")]
    fn terminate_all(mut self) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send>> {
        Box::pin(
            async move {
                if self.regions.is_empty() {
                    return Ok(());
                }

                let res =
                    futures_util::future::join_all(self.regions.drain().map(|(region, mut rl)| {
                        let region_span = tracing::debug_span!("region", %region);
                        async move { rl.terminate_all().await }.instrument(region_span)
                    }))
                    .await;
                res.into_iter().fold(Ok(()), |acc, x| match acc {
                    Ok(_) => x,
                    Err(a) => match x {
                        Ok(_) => Err(a),
                        Err(e) => Err(a.wrap_err(e)),
                    },
                })
            }
            .in_current_span(),
        )
    }
}

#[derive(Debug, Clone)]
struct IpInfo {
    public_dns: String,
    public_ip: String,
    private_ip: String,
}

// Internal representation of an instance.
//
// Tagged with its nickname, and ip_info gets populated once it is available.
#[derive(Debug, Clone)]
struct TaggedSetup {
    name: String,
    setup: Setup,
    ip_info: Option<IpInfo>,
}

/// Region specific. Launch AWS EC2 instances.
///
/// This implementation uses [rusoto](https://crates.io/crates/rusoto_core) to connect to AWS.
///
/// By default, `RegionLauncher` launches uses AWS [defined
/// duration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-requests.html#fixed-duration-spot-instances)
/// spot instances. These cost slightly more than regular spot instances, but are never prematurely
/// terminated.  The lifetime of such instances must be declared in advance (1-6 hours). By
/// default, we use 6 hours (the maximum). To change this, or to switch to on-demand instances, use
/// [`Launcher::set_mode`].
///
/// You must call [`RegionLauncher::shutdown`] to terminate the instances.
#[derive(Educe, Default)]
#[educe(Debug)]
pub struct RegionLauncher {
    /// The region this RegionLauncher is connected to.
    pub region: rusoto_core::region::Region,
    availability_zone: AvailabilityZoneSpec,
    security_group_id: String,
    ssh_key_name: String,
    private_key_path: Option<tempfile::NamedTempFile>,
    #[educe(Debug(ignore))]
    client: Option<rusoto_ec2::Ec2Client>,
    spot_requests: HashMap<String, TaggedSetup>,
    instances: HashMap<String, TaggedSetup>,
}

impl RegionLauncher {
    /// Connect to AWS region `region`, using credentials provider `provider`.
    ///
    /// This is a lower-level API, you may want [`Launcher`] instead.
    ///
    /// This will create a temporary security group and SSH key in the given AWS region.
    pub async fn new<P>(
        region: &str,
        availability_zone: AvailabilityZoneSpec,
        provider: P,
        use_open_ports: bool,
    ) -> Result<Self, Report>
    where
        P: ProvideAwsCredentials + Send + Sync + 'static,
    {
        let region = region.parse()?;
        let ec2 = RegionLauncher::connect(region, availability_zone, provider)
            .wrap_err("failed to connect to region")?
            .make_security_group(use_open_ports)
            .await
            .wrap_err("failed to make security groups")?
            .make_ssh_key()
            .await
            .wrap_err("failed to make ssh key")?;

        Ok(ec2)
    }

    #[instrument(level = "debug", skip(provider))]
    fn connect<P>(
        region: rusoto_core::region::Region,
        availability_zone: AvailabilityZoneSpec,
        provider: P,
    ) -> Result<Self, Report>
    where
        P: ProvideAwsCredentials + Send + Sync + 'static,
    {
        tracing::debug!("connecting to ec2");
        let ec2 = rusoto_ec2::Ec2Client::new_with(
            HttpClient::new().wrap_err("failed to construct new http client")?,
            provider,
            region.clone(),
        );

        Ok(Self {
            region,
            availability_zone,
            security_group_id: Default::default(),
            ssh_key_name: Default::default(),
            private_key_path: Some(
                tempfile::NamedTempFile::new()
                    .wrap_err("failed to create temporary file for keypair")?,
            ),
            spot_requests: Default::default(),
            instances: Default::default(),
            client: Some(ec2),
        })
    }

    /// Region-specific instance setup.
    ///
    /// Make spot instance requests, wait for the instances, and then call the
    /// instance setup functions.
    #[instrument(level = "debug", skip(self, max_wait))]
    pub async fn launch<M>(
        &mut self,
        mode: LaunchMode,
        mut max_wait: Option<time::Duration>,
        machines: M,
    ) -> Result<(), Report>
    where
        M: IntoIterator<Item = (String, Setup)> + std::fmt::Debug,
    {
        let machines: Vec<_> = machines.into_iter().collect();
        let machines = machines.clone();
        let mut do_ondemand = false;
        match mode {
            LaunchMode::TrySpot {
                hours: max_instance_duration_hours,
            }
            | LaunchMode::DefinedDuration {
                hours: max_instance_duration_hours,
            } => {
                let machines = machines.clone();
                self.make_spot_instance_requests(
                    max_instance_duration_hours * 60, // 60 mins/hr
                    machines,
                )
                .await
                .wrap_err("failed to make spot instance requests")?;

                let start = time::Instant::now();
                if let Err(e) = self
                    .wait_for_spot_instance_requests(max_wait)
                    .await
                    .wrap_err(eyre!(
                        "failed while waiting for spot instances fulfilment in {}",
                        self.region.name()
                    ))
                {
                    // if wait_for_spot_instance_requests returned an Err, it will have cleaned up
                    // the spot instance requests already.
                    if let LaunchMode::TrySpot { .. } = mode {
                        tracing::debug!(err = ?e, "re-trying with OnDemand instace");
                        do_ondemand = true;
                    }

                    Err(e)?;
                }

                if let Some(ref mut d) = max_wait {
                    *d -= time::Instant::now().duration_since(start);
                }
            }
            LaunchMode::OnDemand => {
                do_ondemand = true;
            }
        }

        if do_ondemand {
            self.make_on_demand_requests(machines)
                .await
                .wrap_err(eyre!(
                    "failed to start on demand instances in {}",
                    self.region.name()
                ))?;

            // give EC2 a bit of time to discover the instances
            tokio::time::delay_for(std::time::Duration::from_secs(5)).await;
        }

        self.wait_for_instances(max_wait)
            .await
            .wrap_err("failed while waiting for instances to come up")?;
        Ok(())
    }

    #[instrument(level = "trace", skip(self))]
    async fn make_security_group(mut self, use_open_ports: bool) -> Result<Self, Report> {
        let ec2 = self.client.as_mut().expect("RegionLauncher unconnected");

        // set up network firewall for machines
        let group_name = super::rand_name("security");
        tracing::debug!(name = %group_name, "creating security group");
        let mut req = rusoto_ec2::CreateSecurityGroupRequest::default();
        req.group_name = group_name;
        req.description = "temporary access group for tsunami VMs".to_string();
        let res = ec2
            .create_security_group(req)
            .await
            .wrap_err("failed to create security group for new machines")?;
        let group_id = res
            .group_id
            .expect("aws created security group with no group id");
        tracing::trace!(id = %group_id, "security group created");

        let mut req = rusoto_ec2::AuthorizeSecurityGroupIngressRequest::default();
        req.group_id = Some(group_id.clone());

        // icmp access
        req.ip_protocol = Some("icmp".to_string());
        req.from_port = Some(-1);
        req.to_port = Some(-1);
        req.cidr_ip = Some("0.0.0.0/0".to_string());
        tracing::trace!("adding icmp access");
        ec2.authorize_security_group_ingress(req.clone())
            .await
            .wrap_err("failed to fill in security group for new machines")?;

        // allow SSH from anywhere
        req.ip_protocol = Some("tcp".to_string());
        req.from_port = Some(22);
        req.to_port = Some(22);
        req.cidr_ip = Some("0.0.0.0/0".to_string());
        tracing::trace!("adding ssh access");
        ec2.authorize_security_group_ingress(req.clone())
            .await
            .wrap_err("failed to fill in security group for new machines")?;

        // The default VPC uses IPs in range 172.31.0.0/16:
        // https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html
        // TODO(might-be-nice) Support configurable rules for other VPCs
        req.ip_protocol = Some("tcp".to_string());
        req.from_port = Some(0);
        req.to_port = Some(65535);
        if use_open_ports {
            req.cidr_ip = Some("0.0.0.0/0".to_string());
        } else {
            req.cidr_ip = Some("172.31.0.0/16".to_string());
        }

        tracing::trace!("adding intra-vm tcp access");
        ec2.authorize_security_group_ingress(req.clone())
            .await
            .wrap_err("failed to fill in security group for new machines")?;

        req.ip_protocol = Some("udp".to_string());
        req.from_port = Some(0);
        req.to_port = Some(65535);
        if use_open_ports {
            req.cidr_ip = Some("0.0.0.0/0".to_string());
        } else {
            req.cidr_ip = Some("172.31.0.0/16".to_string());
        }

        tracing::trace!("adding intra-vm udp access");
        ec2.authorize_security_group_ingress(req)
            .await
            .wrap_err("failed to fill in security group for new machines")?;

        self.security_group_id = group_id;
        Ok(self)
    }

    #[instrument(level = "trace", skip(self))]
    async fn make_ssh_key(mut self) -> Result<Self, Report> {
        let ec2 = self.client.as_mut().expect("RegionLauncher unconnected");
        let private_key_path = self
            .private_key_path
            .as_mut()
            .expect("RegionLauncher unconnected");

        // construct keypair for ssh access
        tracing::debug!("creating keypair");
        let mut req = rusoto_ec2::CreateKeyPairRequest::default();
        let key_name = super::rand_name("key");
        req.key_name = key_name.clone();
        let res = ec2
            .create_key_pair(req)
            .await
            .context("failed to generate new key pair")?;
        tracing::trace!(fingerprint = ?res.key_fingerprint, "created keypair");

        // write keypair to disk
        let private_key = res
            .key_material
            .expect("aws did not generate key material for new key");
        private_key_path
            .write_all(private_key.as_bytes())
            .context("could not write private key to file")?;
        tracing::debug!(
            filename = %private_key_path.path().display(),
            "wrote keypair to file"
        );

        self.ssh_key_name = key_name;
        Ok(self)
    }

    /// Make a new placement for a launch request.
    ///
    /// This method takes a "placement maker" (`mk`) to allow using this method for both
    /// `SpotPlacement` and `Placement`. The `mk` function is passed a placement name and an
    /// availability zone, and is expected to return an appropriate placement type.
    #[instrument(level = "trace", skip(self, mk))]
    async fn make_placement<R>(
        &mut self,
        mk: impl FnOnce(String, Option<String>) -> R,
    ) -> Result<Option<R>, Report> {
        if let AvailabilityZoneSpec::Any = self.availability_zone {
            Ok(None)
        } else {
            let ec2 = self.client.as_mut().expect("RegionLauncher unconnected");
            tracing::trace!("creating placement group");
            let mut req = rusoto_ec2::CreatePlacementGroupRequest::default();
            let placement_name = super::rand_name("placement");
            req.group_name = Some(placement_name.clone());
            req.strategy = Some(String::from("cluster"));
            ec2.create_placement_group(req).await?;
            tracing::trace!("created placement group");

            Ok(Some(mk(
                placement_name,
                match self.availability_zone {
                    AvailabilityZoneSpec::Cluster(_) => None,
                    AvailabilityZoneSpec::Specify(ref av) => Some(av.clone()),
                    _ => unreachable!(),
                },
            )))
        }
    }

    fn for_each_machine_group<M>(
        machines: M,
    ) -> impl Iterator<Item = ((String, String), Vec<(String, Setup)>)> + Send
    where
        M: IntoIterator<Item = (String, Setup)>,
        M: std::fmt::Debug,
    {
        // minimize the number of instance requests:
        machines
            .into_iter()
            .map(|(name, m)| {
                // attach labels (ami name, instance type):
                // the only fields that vary between tsunami spot instance requests
                ((m.ami.clone(), m.instance_type.clone()), (name, m))
            })
            .into_group_map()
            .into_iter()
    }

    #[instrument(level = "trace", skip(self))]
    async fn make_on_demand_requests<M>(&mut self, machines: M) -> Result<(), Report>
    where
        M: IntoIterator<Item = (String, Setup)>,
        M: std::fmt::Debug,
    {
        tracing::info!("launching on demand instances");

        // minimize the number of instance requests:
        for ((ami, instance_type), reqs) in Self::for_each_machine_group(machines) {
            let inst_span = tracing::debug_span!("run_instance", ?ami, ?instance_type);
            async {
                // and issue one spot request per group
                let mut req = rusoto_ec2::RunInstancesRequest::default();
                req.image_id = Some(ami);
                req.instance_type = Some(instance_type);
                req.placement = self
                    .make_placement(|group_name, az| rusoto_ec2::Placement {
                        group_name: Some(group_name),
                        availability_zone: az,
                        ..Default::default()
                    })
                    .await
                    .wrap_err("create new placement group")?;
                req.security_group_ids = Some(vec![self.security_group_id.clone()]);
                req.key_name = Some(self.ssh_key_name.clone());
                req.min_count = reqs.len() as i64;
                req.max_count = reqs.len() as i64;
                req.instance_initiated_shutdown_behavior = Some("terminate".to_string());

                // TODO: VPC

                tracing::trace!("issuing request");
                let res = self
                    .client
                    .as_mut()
                    .unwrap()
                    .run_instances(req)
                    .await
                    .wrap_err("failed to request on demand instances")?;

                // collect for length check below
                let instances: Vec<String> = res
                    .instances
                    .expect("run_instances should always return instances")
                    .into_iter()
                    .filter_map(|i| i.instance_id)
                    .inspect(|instance_id| {
                        tracing::trace!(id = %instance_id, "launched on-demand instance");
                    })
                    .collect();

                // zip_eq will panic if lengths not equal, so check beforehand
                eyre::ensure!(
                    instances.len() == reqs.len(),
                    "Got {} instances but expected {}",
                    instances.len(),
                    reqs.len(),
                );

                self.instances
                    .extend(instances.into_iter().zip_eq(reqs.into_iter()).map(
                        |(instance_id, (name, setup))| {
                            let setup = TaggedSetup {
                                name,
                                setup,
                                ip_info: None,
                            };
                            (instance_id, setup)
                        },
                    ));

                Ok(())
            }
            .instrument(inst_span)
            .await?;
        }

        Ok(())
    }

    /// Make one-time spot instance requests, which will automatically get terminated after
    /// `max_duration` minutes.
    ///
    /// `machines` is a key-value iterator: keys are friendly names for the machines, and values
    /// are [`Setup`] describing each machine to launch. Once the machines launch,
    /// the friendly names are tied to SSH connections ([`crate::Machine`]) in the `HashMap` that
    /// [`connect_all`](RegionLauncher::connect_all) returns.
    ///
    /// Will *not* wait for the spot instance requests to complete. To wait, call
    /// [`wait_for_spot_instance_requests`](RegionLauncher::wait_for_spot_instance_requests).
    #[instrument(level = "trace", skip(self, max_duration))]
    async fn make_spot_instance_requests<M>(
        &mut self,
        max_duration: usize,
        machines: M,
    ) -> Result<(), Report>
    where
        M: IntoIterator<Item = (String, Setup)>,
        M: std::fmt::Debug,
    {
        tracing::info!("launching spot requests");

        // minimize the number of spot requests:
        for ((ami, instance_type), reqs) in Self::for_each_machine_group(machines) {
            let spot_span = tracing::debug_span!("spot_request", ?ami, ?instance_type);
            async {
                // and issue one spot request per group
                let mut launch = rusoto_ec2::RequestSpotLaunchSpecification::default();
                launch.image_id = Some(ami);
                launch.instance_type = Some(instance_type);
                launch.placement = self
                    .make_placement(|group_name, az| rusoto_ec2::SpotPlacement {
                        group_name: Some(group_name),
                        availability_zone: az,
                        ..Default::default()
                    })
                    .await
                    .wrap_err("create new placement group")?;
                launch.security_group_ids = Some(vec![self.security_group_id.clone()]);
                launch.key_name = Some(self.ssh_key_name.clone());

                // TODO: VPC

                let req = rusoto_ec2::RequestSpotInstancesRequest {
                    instance_count: Some(reqs.len() as i64),
                    block_duration_minutes: Some(max_duration as i64),
                    launch_specification: Some(launch),
                    // one-time spot instances are only fulfilled once and therefore do not need to be
                    // cancelled.
                    type_: Some("one-time".into()),
                    ..Default::default()
                };

                tracing::trace!("issuing spot request");
                let res = self
                    .client
                    .as_mut()
                    .unwrap()
                    .request_spot_instances(req)
                    .await
                    .wrap_err("failed to request spot instance")?;

                // collect for length check below
                let spot_instance_requests: Vec<String> = res
                    .spot_instance_requests
                    .expect("request_spot_instances should always return spot instance requests")
                    .into_iter()
                    .filter_map(|sir| sir.spot_instance_request_id)
                    .inspect(|request_id| {
                        tracing::trace!(id = %request_id, "activated spot request");
                    })
                    .collect();

                // zip_eq will panic if lengths not equal, so check beforehand
                eyre::ensure!(
                    spot_instance_requests.len() == reqs.len(),
                    "Got {} spot instance requests but expected {}",
                    spot_instance_requests.len(),
                    reqs.len(),
                );

                for (request_id, (name, setup)) in
                    spot_instance_requests.into_iter().zip_eq(reqs.into_iter())
                {
                    self.spot_requests.insert(
                        request_id,
                        TaggedSetup {
                            name,
                            setup,
                            ip_info: None,
                        },
                    );
                }

                Ok(())
            }
            .instrument(spot_span)
            .await?;
        }

        Ok(())
    }

    /// Poll AWS once a second until either `max_wait` (if not `None`) elapses, or
    /// the spot requests are fulfilled.
    ///
    /// This method will return when the spot requests are fulfilled, *not* when the instances are
    /// ready.
    ///
    /// To wait for the instances to be ready, call
    /// [`wait_for_instances`](RegionLauncher::wait_for_instances).
    #[instrument(level = "trace", skip(self, max_wait))]
    async fn wait_for_spot_instance_requests(
        &mut self,
        max_wait: Option<time::Duration>,
    ) -> Result<(), Report> {
        tracing::info!("waiting for instances to spawn");

        let start = time::Instant::now();

        loop {
            tracing::trace!("checking spot request status");
            let instances = self.describe_spot_instance_requests().await?;

            let mut any_pending = false;
            for (request_id, state, status, instance_id) in &instances {
                match &**state {
                    "active" if instance_id.is_some() => {
                        tracing::trace!(%request_id, %state, ?instance_id, "spot instance request ready");
                    }
                    "active" | "open" => {
                        any_pending = true;
                    }
                    s => {
                        // closed | failed | cancelled
                        let _ = self.cancel_spot_instance_requests().await;
                        eyre::bail!("spot request unexpectedly {}: {}", s, status);
                    }
                }
            }
            let all_active = !any_pending;

            if all_active {
                // unwraps okay because they are the same as expects above
                self.instances = instances
                    .into_iter()
                    .map(|(request_id, state, _, instance_id)| {
                        assert_eq!(state, "active");
                        let instance_id = instance_id.unwrap();
                        let setup = self.spot_requests[&request_id].clone();
                        (instance_id, setup)
                    })
                    .collect();
                break;
            }

            // let's not hammer the API
            tokio::time::delay_for(time::Duration::from_secs(1)).await;

            if let Some(wait_limit) = max_wait {
                if start.elapsed() <= wait_limit {
                    continue;
                }
                self.cancel_spot_instance_requests().await?;
                eyre::bail!("wait limit reached");
            }
        }

        Ok(())
    }

    /// Poll AWS until `max_wait` (if not `None`) or the instances are ready to SSH to.
    #[instrument(level = "trace", skip(self, max_wait))]
    async fn wait_for_instances(&mut self, max_wait: Option<time::Duration>) -> Result<(), Report> {
        let start = time::Instant::now();
        let mut desc_req = rusoto_ec2::DescribeInstancesRequest::default();
        let client = self.client.as_ref().unwrap();
        let private_key_path = self.private_key_path.as_ref().unwrap();
        let mut all_ready = self.instances.is_empty();
        desc_req.instance_ids = Some(self.instances.keys().cloned().collect());
        while !all_ready {
            all_ready = true;

            for reservation in client
                .describe_instances(desc_req.clone())
                .await
                .wrap_err("could not query AWS for instance state")?
                .reservations
                .unwrap_or_else(Vec::new)
            {
                for instance in reservation.instances.unwrap_or_else(Vec::new) {
                    match instance {
                        // https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_InstanceState.html
                        // code 16 means "Running"
                        rusoto_ec2::Instance {
                            state: Some(rusoto_ec2::InstanceState { code: Some(16), .. }),
                            instance_id: Some(instance_id),
                            public_dns_name: Some(public_dns),
                            public_ip_address: Some(public_ip),
                            private_ip_address: Some(private_ip),
                            ..
                        } => {
                            let instance_span =
                                tracing::debug_span!("instance", %instance_id, ip = %public_ip);
                            let instances = &mut self.instances;
                            async {
                                tracing::trace!("instance running");

                                // try connecting. If can't, not ready.
                                let tag_setup = instances.get_mut(&instance_id).unwrap();

                                // no need to set public dns nor private ip since `connect_ssh` only uses the public ip
                                let m = crate::MachineDescriptor {
                                    nickname: Default::default(),
                                    public_dns: Default::default(),
                                    public_ip: public_ip.to_string(),
                                    private_ip: Default::default(),
                                    _tsunami: Default::default(),
                                };

                                if let Err(e) = m
                                    .connect_ssh(
                                        &tag_setup.setup.username,
                                        Some(private_key_path.path()),
                                        max_wait,
                                        22,
                                    )
                                    .await
                                {
                                    tracing::trace!("ssh failed: {}", e);
                                    all_ready = false;
                                } else {
                                    tracing::debug!("instance ready");

                                    tag_setup.ip_info = Some(IpInfo {
                                        public_dns: public_dns.clone(),
                                        public_ip: public_ip.clone(),
                                        private_ip: private_ip.clone(),
                                    });
                                }
                            }
                            .instrument(instance_span)
                            .await
                        }
                        _ => {
                            all_ready = false;
                        }
                    }
                }
            }

            // let's not hammer the API
            tokio::time::delay_for(time::Duration::from_secs(1)).await;

            if let Some(wait_limit) = max_wait {
                if start.elapsed() <= wait_limit {
                    continue;
                }
                self.cancel_spot_instance_requests().await?;
                eyre::bail!("wait limit reached");
            }
        }

        futures_util::future::join_all(self.instances.iter().map(
            |(
                instance_id,
                TaggedSetup {
                    ip_info,
                    name,
                    setup,
                },
            )| {
                let IpInfo {
                    public_dns,
                    public_ip,
                    private_ip,
                } = ip_info.as_ref().unwrap();
                let instance_span = tracing::debug_span!("instance", %instance_id, ip = %public_ip);
                async move {
                    if let Setup {
                        username,
                        setup_fn: Some(f),
                        ..
                    } = setup
                    {
                        super::setup_machine(
                            &name,
                            Some(&public_dns),
                            &public_ip,
                            Some(&private_ip),
                            &username,
                            max_wait,
                            Some(private_key_path.path()),
                            f.as_ref(),
                        )
                        .await?;
                    }

                    Ok(())
                }
                .instrument(instance_span)
            },
        ))
        .await
        .into_iter()
        .collect()
    }

    /// Establish SSH connections to the machines. The `Ok` value is a `HashMap` associating the
    /// friendly name for each `Setup` with the corresponding SSH connection.
    #[instrument(level = "debug")]
    pub async fn connect_all<'l>(&'l self) -> Result<HashMap<String, crate::Machine<'l>>, Report> {
        let private_key_path = self.private_key_path.as_ref().unwrap();
        futures_util::future::join_all(self.instances.values().map(|info| {
            let instance_span = tracing::trace_span!("instance", name = %info.name);
            async move {
                match info {
                    TaggedSetup {
                        name,
                        setup: Setup { username, .. },
                        ip_info:
                            Some(IpInfo {
                                public_dns,
                                public_ip,
                                private_ip,
                            }),
                    } => {
                        let m = crate::MachineDescriptor {
                            public_dns: Some(public_dns.clone()),
                            public_ip: public_ip.clone(),
                            private_ip: Some(private_ip.clone()),
                            nickname: name.clone(),
                            _tsunami: Default::default(),
                        };

                        let m = m
                            .connect_ssh(&username, Some(private_key_path.path()), None, 22)
                            .await?;
                        Ok((name.clone(), m))
                    }
                    _ => eyre::bail!("machine has no ip information"),
                }
            }
            .instrument(instance_span)
        }))
        .await
        .into_iter()
        .collect()
    }

    /// Terminate all running instances.
    ///
    /// Additionally deletes ephemeral keys and security groups. Sometimes, this deletion can fail
    /// for various reasons. This method deletes things in this order:
    /// 1. Try to delete the key pair, but emit a log message and continue if it fails.
    /// 2. Try to terminate the instances, and short-circuits to return the error if it fails.
    /// 3. Try to delete the security group. This can fail as the security groups are still
    ///    "attached" to the instances we just terminated in step 2. So, we retry for 2 minutes
    ///    before giving up and returning an error.
    #[instrument(level = "debug")]
    pub async fn terminate_all(&mut self) -> Result<(), Report> {
        let client = self.client.as_ref().unwrap();

        if !self.ssh_key_name.trim().is_empty() {
            let key_span = tracing::trace_span!("key", name = %self.ssh_key_name);
            async {
                tracing::trace!("removing keypair");
                let mut req = rusoto_ec2::DeleteKeyPairRequest::default();
                req.key_name = Some(self.ssh_key_name.clone());
                if let Err(e) = client.delete_key_pair(req).await {
                    tracing::warn!("failed to clean up temporary SSH key: {}", e);
                }
            }
            .instrument(key_span)
            .await;
        }

        // terminate instances
        if !self.instances.is_empty() {
            tracing::info!("terminating instances");
            let instance_ids = self.instances.keys().cloned().collect();
            self.instances.clear();
            // Why is `?` here ok? either:
            // 1. there was no spot capacity. So self.instances will be empty, and this
            //    block will get skipped, so sg will get cleaned up below.
            // 2. there were instances, but we couldn't terminate them. Then, the sg will
            //    still be attached to them, so there's no point trying to delete it.
            self.terminate_instances(instance_ids).await?;
        }

        use rusoto_core::RusotoError;
        if !self.security_group_id.trim().is_empty() {
            let group_span =
                tracing::trace_span!("removing security group", id = %self.security_group_id);
            async {
                tracing::trace!("removing security group.");
                // clean up security groups and keys
                let start = tokio::time::Instant::now();
                loop {
                    if start.elapsed() > tokio::time::Duration::from_secs(5 * 60) {
                        Err(Report::msg(
                            "failed to clean up temporary security group after 5 minutes.",
                        ))?;
                        unreachable!();
                    }

                    let mut req = rusoto_ec2::DeleteSecurityGroupRequest::default();
                    req.group_id = Some(self.security_group_id.clone());
                    match client.delete_security_group(req).await {
                        Ok(_) => break,
                        Err(RusotoError::Unknown(r)) => {
                            let err = r.body_as_str();
                            if err.contains("<Code>DependencyViolation</Code>") {
                                tracing::trace!("instances not yet shut down -- retrying");
                                tokio::time::delay_for(tokio::time::Duration::from_secs(5)).await;
                            } else {
                                Err(Report::new(RusotoError::<
                                    rusoto_ec2::DeleteSecurityGroupError,
                                >::Unknown(r)))
                                .wrap_err("failed to clean up temporary security group")?;
                                unreachable!();
                            }
                        }
                        Err(e) => {
                            Err(Report::new(e)
                                .wrap_err("failed to clean up temporary security group"))?;
                            unreachable!();
                        }
                    }
                }

                tracing::trace!("cleaned up temporary security group");
                Ok::<_, Report>(())
            }
            .instrument(group_span)
            .await?;
        }

        Ok(())
    }

    #[instrument(level = "debug")]
    async fn describe_spot_instance_requests(
        &self,
    ) -> Result<Vec<(String, String, String, Option<String>)>, Report> {
        let client = self.client.as_ref().unwrap();
        let request_ids = self.spot_requests.keys().cloned().collect();
        let mut req = rusoto_ec2::DescribeSpotInstanceRequestsRequest::default();
        req.spot_instance_request_ids = Some(request_ids);
        loop {
            let res = client.describe_spot_instance_requests(req.clone()).await;
            if let Err(ref e) = res {
                let msg = e.to_string();
                if msg.contains("The spot instance request ID") && msg.contains("does not exist") {
                    tracing::trace!("spot instance requests not yet ready");

                    // let's not hammer the API
                    tokio::time::delay_for(time::Duration::from_secs(1)).await;
                    continue;
                } else {
                    res.wrap_err("failed to describe spot instances")?;
                    unreachable!();
                }
            }

            let res = res.expect("Err checked above");
            let instances = res
                .spot_instance_requests
                .expect("describe always returns at least one spot instance")
                .into_iter()
                .map(|sir| {
                    let request_id = sir
                        .spot_instance_request_id
                        .expect("spot request did not have id specified");
                    let state = sir
                        .state
                        .expect("spot request did not have state specified");
                    let status = sir
                        .status
                        .expect("spot request did not have status specified")
                        .code
                        .expect("spot request status did not have status code");
                    let instance_id = sir.instance_id;
                    (request_id, state, status, instance_id)
                })
                .collect();
            break Ok(instances);
        }
    }

    #[instrument(level = "debug")]
    async fn cancel_spot_instance_requests(&self) -> Result<(), Report> {
        tracing::warn!("wait time exceeded for -- cancelling run");
        if self.spot_requests.is_empty() {
            return Ok(());
        }
        let request_ids = self.spot_requests.keys().cloned().collect();
        let mut cancel = rusoto_ec2::CancelSpotInstanceRequestsRequest::default();
        cancel.spot_instance_request_ids = request_ids;
        self.client
            .as_ref()
            .unwrap()
            .cancel_spot_instance_requests(cancel)
            .await
            .wrap_err("failed to cancel spot instances")?;

        tracing::trace!("spot instances cancelled -- waiting for cancellation");
        loop {
            tracing::trace!("checking spot request status");
            let instances = self.describe_spot_instance_requests().await?;

            let all_cancelled = instances.iter().all(|(request_id, state, _, instance_id)| {
                if state == "closed"
                    || state == "cancelled"
                    || state == "failed"
                    || state == "completed"
                {
                    tracing::trace!(%request_id, ?instance_id, "spot instance request {}", state);
                    true
                } else {
                    false
                }
            });

            if all_cancelled {
                tracing::trace!("deleting spot instances");
                // find instances with an id assigned and terminate them
                let instance_ids = instances
                    .into_iter()
                    .filter_map(|(_, _, _, instance_id)| instance_id)
                    .collect();
                self.terminate_instances(instance_ids).await?;
                break;
            }

            // let's not hammer the API
            tokio::time::delay_for(time::Duration::from_secs(1)).await;
        }
        Ok(())
    }

    #[instrument(level = "debug")]
    async fn terminate_instances(&self, instance_ids: Vec<String>) -> Result<(), Report> {
        if instance_ids.is_empty() {
            return Ok(());
        }
        let client = self.client.as_ref().unwrap();
        let mut termination_req = rusoto_ec2::TerminateInstancesRequest::default();
        termination_req.instance_ids = instance_ids;
        while let Err(e) = client.terminate_instances(termination_req.clone()).await {
            let msg = e.to_string();
            if msg.contains("Pooled stream disconnected") || msg.contains("broken pipe") {
                tracing::trace!("retrying instance termination");
                continue;
            } else {
                Err(e).wrap_err("failed to terminate tsunami instances")?;
                unreachable!();
            }
        }
        Ok(())
    }
}

struct UbuntuAmi(String);

impl UbuntuAmi {
    async fn new(r: Region) -> Result<Self, Report> {
        Ok(UbuntuAmi(
            ubuntu_ami::get_latest(
                &r.name(),
                Some("bionic"),
                None,
                Some("hvm:ebs-ssd"),
                Some("amd64"),
            )
            .await
            .map_err(|e| eyre!(e))?,
        ))
    }
}

impl Into<String> for UbuntuAmi {
    fn into(self) -> String {
        self.0
    }
}

#[cfg(test)]
mod test {
    use super::RegionLauncher;
    use super::*;
    use rusoto_core::credential::DefaultCredentialsProvider;
    use rusoto_core::region::Region;
    use rusoto_ec2::Ec2;
    use std::future::Future;

    fn do_make_machine_and_ssh_setupfn<'l>(
        l: &'l mut super::Launcher,
    ) -> impl Future<Output = Result<(), Report>> + 'l {
        use crate::providers::Launcher;
        async move {
            l.spawn(
                vec![(
                    String::from("my machine"),
                    super::Setup::default().setup(|vm| {
                        Box::pin(async move {
                            if vm.ssh.command("whoami").status().await?.success() {
                                Ok(())
                            } else {
                                Err(eyre!("failed"))
                            }
                        })
                    }),
                )],
                None,
            )
            .await?;
            let vms = l.connect_all().await?;
            let my_machine = vms
                .get("my machine")
                .ok_or_else(|| eyre!("machine not found"))?;
            my_machine
                .ssh
                .command("echo")
                .arg("\"Hello, EC2\"")
                .status()
                .await?;

            Ok(())
        }
    }

    #[test]
    #[ignore]
    fn make_machine_and_ssh_setupfn() {
        use crate::providers::Launcher;
        tracing_subscriber::fmt::init();
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        let mut l = super::Launcher::default();
        // make the defined-duration instances expire after 1 hour
        l.set_mode(LaunchMode::duration_spot(1));
        rt.block_on(async move {
            if let Err(e) = do_make_machine_and_ssh_setupfn(&mut l).await {
                // failed test.
                l.terminate_all().await.unwrap();
                panic!(e);
            } else {
                l.terminate_all().await.unwrap();
            }
        })
    }

    #[test]
    #[ignore]
    fn make_key() -> Result<(), Report> {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        let region = Region::UsEast1;
        let provider = DefaultCredentialsProvider::new()?;
        let ec2 = RegionLauncher::connect(region, super::AvailabilityZoneSpec::Any, provider)?;
        rt.block_on(async {
            let mut ec2 = ec2.make_ssh_key().await?;
            tracing::debug!(
                name = %ec2.ssh_key_name,
                path = %ec2.private_key_path.as_ref().unwrap().path().display(),
                "made key"
            );
            assert!(!ec2.ssh_key_name.is_empty());
            assert!(ec2.private_key_path.as_ref().unwrap().path().exists());

            let mut req = rusoto_ec2::DeleteKeyPairRequest::default();
            req.key_name = Some(ec2.ssh_key_name.clone());
            ec2.client
                .as_mut()
                .unwrap()
                .delete_key_pair(req)
                .await
                .context(format!(
                    "Could not delete ssh key pair {:?}",
                    ec2.ssh_key_name
                ))?;

            Ok(())
        })
    }

    fn do_multi_instance_spot_request<'l>(
        ec2: &'l mut super::RegionLauncher,
    ) -> impl Future<Output = Result<(), Report>> + 'l {
        async move {
            let names = (1..).map(|x| format!("{}", x));
            let setup = Setup::default();
            let ms: Vec<(String, Setup)> = names.zip(itertools::repeat_n(setup, 5)).collect();

            tracing::debug!(num = %ms.len(), "make spot instance requests");
            ec2.make_spot_instance_requests(60 as _, ms).await?;
            assert_eq!(ec2.spot_requests.len(), 5);
            tracing::debug!("wait for spot instance requests");
            ec2.wait_for_spot_instance_requests(None).await?;

            Ok(())
        }
    }

    #[test]
    #[ignore]
    fn multi_instance_spot_request() -> Result<(), Report> {
        let region = "us-east-1";
        let provider = DefaultCredentialsProvider::new()?;

        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut ec2 =
                RegionLauncher::new(region, super::AvailabilityZoneSpec::Any, provider, false)
                    .await?;

            if let Err(e) = do_multi_instance_spot_request(&mut ec2).await {
                ec2.terminate_all().await.unwrap();
                panic!(e);
            } else {
                ec2.terminate_all().await.unwrap();
            }

            Ok(())
        })
    }
}
