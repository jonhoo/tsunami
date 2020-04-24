//! AWS backend for tsunami.
//!
//! The primary `impl Launcher` type is [`Launcher`].
//! It internally uses the lower-level, region-specific [`aws::RegionLauncher`].
//! Both these types use [`aws::Setup`] as their descriptor type.
//!
//! This implementation uses [defined duration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-requests.html#fixed-duration-spot-instances)
//! instances.
//!
//! # Examples
//! ```rust,no_run
//! #[tokio::main]
//! async fn main() {
//!     use tsunami::providers::{aws, Launcher};
//!
//!     let mut l = aws::Launcher::default();
//!     // make the defined-duration instances expire after 1 hour
//!     l.set_max_instance_duration(1);
//!     l.spawn(vec![(String::from("my machine"), aws::Setup::default())], None, None)
//!         .await.unwrap();
//!     let vms = l.connect_all().await.unwrap();
//!     let my_machine = vms.get("my machine").unwrap();
//!     let out = my_machine
//!         .ssh
//!         .as_ref()
//!         .unwrap()
//!         .command("echo")
//!         .arg("\"Hello, EC2\"")
//!         .output()
//!         .await
//!         .unwrap();
//!     let stdout = std::string::String::from_utf8(out.stdout).unwrap();
//!     println!("{}", stdout);
//!     l.cleanup().await.unwrap();
//! }
//! ```
//! ```rust,no_run
//! use tsunami::providers::{Launcher, aws};
//! use rusoto_core::{credential::DefaultCredentialsProvider, Region};
//! #[tokio::main]
//! async fn main() -> Result<(), failure::Error> {
//!     // Initialize AWS
//!     let mut aws = aws::Launcher::default();
//!     // make the defined-duration instances expire after 1 hour
//!     // default is the maximum (6 hours)
//!     aws.set_max_instance_duration(1).open_ports();
//!
//!     // Create a machine descriptor and add it to the Tsunami
//!     let m = aws::Setup::default()
//!         .region_with_ubuntu_ami(Region::UsWest1) // default is UsEast1
//!         .setup(|ssh, _| { // default is a no-op
//!             Box::pin(async move {
//!                 ssh.command("sudo").arg("apt").arg("update").status().await?;
//!                 ssh.command("bash").arg("-c")
//!                     .arg("\"curl https://sh.rustup.rs -sSf | sh -- -y\"").status().await?;
//!                 Ok(())
//!             })
//!         });
//!
//!     // Launch the VM
//!     aws.spawn(vec![(String::from("my_vm"), m)], None, None).await?;
//!
//!     // SSH to the VM and run a command on it
//!     let vms = aws.connect_all().await?;
//!     let my_vm = vms.get("my_vm").unwrap();
//!     println!("public ip: {}", my_vm.public_ip);
//!     let ssh = my_vm.ssh.as_ref().unwrap();
//!     ssh.command("git").arg("clone").arg("https://github.com/jonhoo/tsunami").status().await?;
//!     ssh.command("bash").arg("-c").arg("\"cd tsunami && cargo build\"").status().await?;
//!     aws.cleanup().await?;
//!     Ok(())
//! }
//! ```

use crate::ssh;
use crate::Machine;
use educe::Educe;
use failure::{Error, ResultExt};
use itertools::Itertools;
use rusoto_core::credential::{DefaultCredentialsProvider, ProvideAwsCredentials};
use rusoto_core::request::HttpClient;
use rusoto_core::Region;
use rusoto_ec2::Ec2;
use std::collections::HashMap;
use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
use std::{thread, time};

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
    Specify(String),
}

impl Default for AvailabilityZoneSpec {
    fn default() -> Self {
        Self::Any
    }
}

/// A descriptor for a particular machine setup in a tsunami.
///
/// An AMI and username must be set (indicated by marker type [`Yes`]) for this to be useful.
/// The default region and ami is Ubuntu 18.04 LTS in us-east-1. Users can call one of:
/// - [`Setup::region_with_ubuntu_ami`]
/// - [`Setup::ami`]
/// - [`Setup::region`] followed by [`Setup::ami`]
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
                    &'r mut ssh::Session,
                    &'r slog::Logger,
                )
                    -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'r>>
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
            ami: UbuntuAmi::from(Region::UsEast1).into(),
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
    /// here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions)
    ///
    /// AMIs are region-specific. This will overwrite the ami field to
    /// the Ubuntu 18.04 LTS AMI in the selected region.
    pub fn region_with_ubuntu_ami(mut self, region: Region) -> Self {
        self.region = region.clone();
        let ami: String = UbuntuAmi::from(region).into();
        self.ami(ami, "ubuntu")
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
    /// let m = Setup::default()
    ///     .setup(|ssh, log| { Box::pin(async move {
    ///         slog::info!(log, "running setup!");
    ///         ssh.command("sudo").arg("apt").arg("update").status().await?;
    ///         Ok(())
    ///     })});
    /// ```
    pub fn setup(
        mut self,
        setup: impl for<'r> Fn(
                &'r mut ssh::Session,
                &'r slog::Logger,
            ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'r>>
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
#[derive(Educe)]
#[educe(Debug)]
pub struct Launcher<P = DefaultCredentialsProvider> {
    #[educe(Debug(ignore))]
    credential_provider: Box<dyn Fn() -> Result<P, Error>>,
    max_instance_duration_hours: usize,
    use_open_ports: bool,
    regions: HashMap<<Setup as super::MachineSetup>::Region, RegionLauncher>,
}

impl Default for Launcher {
    fn default() -> Self {
        Launcher {
            credential_provider: Box::new(|| Ok(DefaultCredentialsProvider::new()?)),
            max_instance_duration_hours: 6,
            use_open_ports: false,
            regions: Default::default(),
        }
    }
}

impl<P> Launcher<P> {
    /// `Launcher` uses [defined duration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-requests.html#fixed-duration-spot-instances)
    /// instances.
    ///
    /// The lifetime of such instances must be declared in advance (1-6 hours).
    /// This method thus clamps `t` to be between 1 and 6.
    ///
    /// By default, we use 6 hours (the maximum).
    pub fn set_max_instance_duration(&mut self, t: usize) -> &mut Self {
        let t = std::cmp::min(t, 6);
        let t = std::cmp::max(t, 1);
        self.max_instance_duration_hours = t;
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
    pub fn with_credentials<P2>(self, f: impl Fn() -> Result<P2, Error> + 'static) -> Launcher<P2> {
        Launcher {
            credential_provider: Box::new(f),
            max_instance_duration_hours: self.max_instance_duration_hours,
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

    fn launch<'l>(
        &'l mut self,
        l: super::LaunchDescriptor<Self::MachineDescriptor>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + 'l>> {
        Box::pin(async move {
            let prov = (*self.credential_provider)()?;
            let Self {
                use_open_ports,
                max_instance_duration_hours,
                ref mut regions,
                ..
            } = self;

            if !regions.contains_key(&l.region) {
                let awsregion = RegionLauncher::new(
                    &l.region.to_string(),
                    // availability_zone spec is guaranteed to be the same because it's included in
                    // the region specifier.
                    l.machines[0].1.availability_zone.clone(),
                    prov,
                    *use_open_ports,
                    l.log,
                )
                .await?;
                regions.insert(l.region.clone(), awsregion);
            }

            regions
                .get_mut(&l.region)
                .unwrap()
                .launch(*max_instance_duration_hours, l.max_wait, l.machines)
                .await?;
            Ok(())
        })
    }

    fn spawn<'l>(
        &'l mut self,
        descriptors: impl IntoIterator<Item = (String, Self::MachineDescriptor)> + 'static,
        max_wait: Option<std::time::Duration>,
        log: Option<slog::Logger>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + 'l>> {
        use super::MachineSetup;
        Box::pin(async move {
            let log = log.unwrap_or_else(|| slog::Logger::root(slog::Discard, o!()));

            info!(log, "spinning up tsunami");

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
                    let region_log = log.new(slog::o!("region" => region_name.clone().to_string()));
                    let prov = (*self.credential_provider)().unwrap();
                    async move {
                        let awsregion = RegionLauncher::new(
                            &region_name.to_string(),
                            // availability_zone spec is guaranteed to be the same because it's included in
                            // the region specifier.
                            s[0].1.availability_zone.clone(),
                            prov,
                            use_open_ports,
                            region_log,
                        )
                        .await?;
                        Ok::<_, Error>((region_name.clone(), awsregion))
                    }
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
            let max_instance_duration_hours = self.max_instance_duration_hours;
            let regions =
                futures_util::future::join_all(haves.into_iter().map(|(region_name, machines)| {
                    // unwrap ok because everything is a have now
                    let mut region_launcher = self.regions.remove(&region_name).unwrap();
                    async move {
                        if let Err(e) = region_launcher
                            .launch(max_instance_duration_hours, max_wait, machines)
                            .await
                        {
                            Err((region_name, region_launcher, e))
                        } else {
                            Ok((region_name, region_launcher))
                        }
                    }
                }))
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
        })
    }

    fn connect_all<'l>(
        &'l self,
    ) -> Pin<Box<dyn Future<Output = Result<HashMap<String, crate::Machine<'l>>, Error>> + 'l>>
    {
        Box::pin(async move { collect!(self.regions) })
    }

    fn cleanup(mut self) -> Pin<Box<dyn Future<Output = Result<(), Error>>>> {
        Box::pin(async move {
            if self.regions.is_empty() {
                return Ok(());
            }

            futures_util::future::join_all(
                self.regions
                    .drain()
                    .map(|(_, mut rl)| async move { rl.shutdown().await }),
            )
            .await;
            Ok(())
        })
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

/// Region specific. Launch AWS EC2 spot instances.
///
/// This implementation uses [rusoto](https://crates.io/crates/rusoto_core) to connect to AWS.
///
/// EC2 spot instances are normally subject to termination at any point. This library instead
/// uses [defined duration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-requests.html#fixed-duration-spot-instances)
/// instances, which cost slightly more, but are never prematurely terminated.  The lifetime of
/// such instances must be declared in advance (1-6 hours). By default, we use 6 hours (the
/// maximum). To change this, RegionLauncher respects the limit specified in
/// [`Launcher::set_max_instance_duration`](Launcher::set_max_instance_duration).
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
    outstanding_spot_request_ids: HashMap<String, TaggedSetup>,
    instances: HashMap<String, TaggedSetup>,
    log: Option<slog::Logger>,
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
        log: slog::Logger,
    ) -> Result<Self, Error>
    where
        P: ProvideAwsCredentials + Send + Sync + 'static,
    {
        let region = region.parse()?;
        let ec2 = RegionLauncher::connect(region, availability_zone, provider, log)?
            .make_security_group(use_open_ports)
            .await?
            .make_ssh_key()
            .await?;

        Ok(ec2)
    }

    fn connect<P>(
        region: rusoto_core::region::Region,
        availability_zone: AvailabilityZoneSpec,
        provider: P,
        log: slog::Logger,
    ) -> Result<Self, Error>
    where
        P: ProvideAwsCredentials + Send + Sync + 'static,
    {
        debug!(log, "connecting to ec2");
        let ec2 = rusoto_ec2::Ec2Client::new_with(HttpClient::new()?, provider, region.clone());

        Ok(Self {
            region,
            availability_zone,
            security_group_id: Default::default(),
            ssh_key_name: Default::default(),
            private_key_path: Some(
                tempfile::NamedTempFile::new()
                    .context("failed to create temporary file for keypair")?,
            ),
            outstanding_spot_request_ids: Default::default(),
            instances: Default::default(),
            client: Some(ec2),
            log: Some(log),
        })
    }

    /// Region-specific instance setup.
    ///
    /// Make spot instance requests, wait for the instances, and then call the
    /// instance setup functions.
    pub async fn launch(
        &mut self,
        max_instance_duration_hours: usize,
        max_wait: Option<time::Duration>,
        machines: impl IntoIterator<Item = (String, Setup)>,
    ) -> Result<(), Error> {
        self.make_spot_instance_requests(
            max_instance_duration_hours * 60, // 60 mins/hr
            machines,
        )
        .await?;

        let start = time::Instant::now();
        self.wait_for_spot_instance_requests(max_wait).await?;
        if let Some(mut d) = max_wait {
            d -= time::Instant::now().duration_since(start);
        }

        self.wait_for_instances(max_wait).await?;
        Ok(())
    }

    async fn make_security_group(mut self, use_open_ports: bool) -> Result<Self, Error> {
        let log = self.log.as_ref().expect("RegionLauncher uninitialized");
        let ec2 = self.client.as_mut().expect("RegionLauncher unconnected");

        // set up network firewall for machines
        let group_name = super::rand_name("security");
        trace!(log, "creating security group"; "name" => &group_name);
        let mut req = rusoto_ec2::CreateSecurityGroupRequest::default();
        req.group_name = group_name;
        req.description = "temporary access group for tsunami VMs".to_string();
        let res = ec2
            .create_security_group(req)
            .await
            .context("failed to create security group for new machines")?;
        let group_id = res
            .group_id
            .expect("aws created security group with no group id");
        trace!(log, "created security group"; "id" => &group_id);

        let mut req = rusoto_ec2::AuthorizeSecurityGroupIngressRequest::default();
        req.group_id = Some(group_id.clone());

        // icmp access
        req.ip_protocol = Some("icmp".to_string());
        req.from_port = Some(-1);
        req.to_port = Some(-1);
        req.cidr_ip = Some("0.0.0.0/0".to_string());
        trace!(log, "adding icmp access to security group");
        ec2.authorize_security_group_ingress(req.clone())
            .await
            .context("failed to fill in security group for new machines")?;

        // allow SSH from anywhere
        req.ip_protocol = Some("tcp".to_string());
        req.from_port = Some(22);
        req.to_port = Some(22);
        req.cidr_ip = Some("0.0.0.0/0".to_string());
        trace!(log, "adding ssh access to security group");
        ec2.authorize_security_group_ingress(req.clone())
            .await
            .context("failed to fill in security group for new machines")?;

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

        trace!(log, "adding internal VM access to security group");
        ec2.authorize_security_group_ingress(req.clone())
            .await
            .context("failed to fill in security group for new machines")?;

        req.ip_protocol = Some("udp".to_string());
        req.from_port = Some(0);
        req.to_port = Some(65535);
        if use_open_ports {
            req.cidr_ip = Some("0.0.0.0/0".to_string());
        } else {
            req.cidr_ip = Some("172.31.0.0/16".to_string());
        }

        trace!(log, "adding internal VM access to security group");
        ec2.authorize_security_group_ingress(req)
            .await
            .context("failed to fill in security group for new machines")?;

        self.security_group_id = group_id;
        Ok(self)
    }

    async fn make_ssh_key(mut self) -> Result<Self, Error> {
        let log = self.log.as_ref().expect("RegionLauncher uninitialized");
        let ec2 = self.client.as_mut().expect("RegionLauncher unconnected");
        let private_key_path = self
            .private_key_path
            .as_mut()
            .expect("RegionLauncher unconnected");

        // construct keypair for ssh access
        trace!(log, "creating keypair");
        let mut req = rusoto_ec2::CreateKeyPairRequest::default();
        let key_name = super::rand_name("key");
        req.key_name = key_name.clone();
        let res = ec2
            .create_key_pair(req)
            .await
            .context("failed to generate new key pair")?;
        trace!(log, "created keypair"; "fingerprint" => res.key_fingerprint);

        // write keypair to disk
        let private_key = res
            .key_material
            .expect("aws did not generate key material for new key");
        private_key_path
            .write_all(private_key.as_bytes())
            .context("could not write private key to file")?;
        debug!(log, "wrote keypair to file"; "filename" => private_key_path.path().display());

        self.ssh_key_name = key_name;
        Ok(self)
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
    async fn make_spot_instance_requests(
        &mut self,
        max_duration: usize,
        machines: impl IntoIterator<Item = (String, Setup)>,
    ) -> Result<(), Error> {
        let log = self.log.as_ref().expect("RegionLauncher uninitialized");

        // minimize the number of spot requests:
        for (_, reqs) in machines
            .into_iter()
            .map(|(name, m)| {
                // attach labels (ami name, instance type):
                // the only fields that vary between tsunami spot instance requests
                ((m.ami.clone(), m.instance_type.clone()), (name, m))
            })
            .into_group_map()
        // group by the labels
        {
            // and issue one spot request per group
            let mut launch = rusoto_ec2::RequestSpotLaunchSpecification::default();
            launch.image_id = Some(reqs[0].1.ami.clone());
            launch.instance_type = Some(reqs[0].1.instance_type.clone());
            launch.placement = {
                if let AvailabilityZoneSpec::Any = self.availability_zone {
                    None
                } else {
                    let ec2 = self.client.as_mut().expect("RegionLauncher unconnected");
                    trace!(log, "creating placement group");
                    let mut req = rusoto_ec2::CreatePlacementGroupRequest::default();
                    let placement_name = super::rand_name("placement");
                    req.group_name = Some(placement_name.clone());
                    req.strategy = Some(String::from("cluster"));
                    ec2.create_placement_group(req)
                        .await
                        .context("failed to create new placement group")?;
                    trace!(log, "created placement group");
                    let mut placement = rusoto_ec2::SpotPlacement::default();
                    placement.group_name = Some(placement_name);
                    match self.availability_zone {
                        AvailabilityZoneSpec::Cluster(_) => {
                            placement.availability_zone = None;
                        }
                        AvailabilityZoneSpec::Specify(ref av) => {
                            placement.availability_zone = Some(av.clone());
                        }
                        _ => unreachable!(),
                    }

                    Some(placement)
                }
            };

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

            trace!(log, "issuing spot request");
            let res = self
                .client
                .as_mut()
                .unwrap()
                .request_spot_instances(req)
                .await
                .context("failed to request spot instance")?;
            let l = log.clone();

            // collect for length check below
            let spot_instance_requests: Vec<String> = res
                .spot_instance_requests
                .expect("request_spot_instances should always return spot instance requests")
                .into_iter()
                .filter_map(|sir| sir.spot_instance_request_id)
                .map(|sir| {
                    // TODO: add more info if in parallel
                    trace!(l, "activated spot request"; "id" => &sir);
                    sir
                })
                .collect();

            // zip_eq will panic if lengths not equal, so check beforehand
            if spot_instance_requests.len() != reqs.len() {
                bail!(
                    "Got {} spot instance requests but expected {}",
                    spot_instance_requests.len(),
                    reqs.len()
                )
            }

            for (sir, req) in spot_instance_requests.into_iter().zip_eq(reqs.into_iter()) {
                self.outstanding_spot_request_ids.insert(
                    sir,
                    TaggedSetup {
                        name: req.0,
                        setup: req.1,
                        ip_info: None,
                    },
                );
            }
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
    async fn wait_for_spot_instance_requests(
        &mut self,
        max_wait: Option<time::Duration>,
    ) -> Result<(), Error> {
        let log = {
            self.log
                .as_ref()
                .expect("RegionLauncher uninitialized")
                .clone()
        };
        let start = time::Instant::now();
        let mut req = rusoto_ec2::DescribeSpotInstanceRequestsRequest::default();
        req.spot_instance_request_ids =
            Some(self.outstanding_spot_request_ids.keys().cloned().collect());
        debug!(log, "waiting for instances to spawn");
        let client = self.client.as_ref().unwrap();

        loop {
            trace!(log, "checking spot request status");

            let res = client.describe_spot_instance_requests(req.clone()).await;
            if let Err(e) = res {
                let msg = format!("{}", e);
                if msg.contains("The spot instance request ID") && msg.contains("does not exist") {
                    trace!(log, "spot instance requests not yet ready");
                    continue;
                } else {
                    return Err(e)
                        .context("failed to describe spot instances")
                        .map_err(|e| e.into());
                }
            }
            let res = res.expect("Err checked above");

            let any_pending = res
                .spot_instance_requests
                .as_ref()
                .expect("describe always returns at least one spot instance")
                .iter()
                .map(|sir| {
                    (
                        sir,
                        sir.state
                            .as_ref()
                            .expect("spot request did not have state specified"),
                    )
                })
                .any(|(sir, state)| {
                    if state == "open" || (state == "active" && sir.instance_id.is_none()) {
                        true
                    } else {
                        trace!(log, "spot request ready"; "state" => state, "id" => &sir.spot_instance_request_id);
                        false
                    }
                });

            if !any_pending {
                // unwraps okay because they are the same as expects above
                self.instances = res
                    .spot_instance_requests
                    .unwrap()
                    .into_iter()
                    .filter_map(|sir| {
                        if sir.state.as_ref().unwrap() == "active" {
                            // unwrap ok because active implies instance_id.is_some()
                            // because !any_pending
                            let instance_id = sir.instance_id.unwrap();
                            trace!(log, "spot request satisfied"; "iid" => &instance_id);

                            Some((
                                instance_id,
                                self.outstanding_spot_request_ids
                                    .remove(&sir.spot_instance_request_id.unwrap())
                                    .unwrap()
                            ))
                        } else {
                            error!(log, "spot request failed: {:?}", &sir.status; "state" => &sir.state.unwrap());
                            None
                        }
                    })
                    .collect();
                break;
            } else {
                thread::sleep(time::Duration::from_secs(1));
            }

            if let Some(wait_limit) = max_wait {
                if start.elapsed() <= wait_limit {
                    continue;
                }

                warn!(log, "wait time exceeded -- cancelling run");
                let mut cancel = rusoto_ec2::CancelSpotInstanceRequestsRequest::default();
                cancel.spot_instance_request_ids = req
                    .spot_instance_request_ids
                    .clone()
                    .expect("we set this to Some above");
                client
                    .cancel_spot_instance_requests(cancel)
                    .await
                    .context("failed to cancel spot instances")
                    .map_err(|e| {
                        warn!(log, "failed to cancel spot instance request: {:?}", e);
                        e
                    })?;

                trace!(
                    log,
                    "spot instances cancelled -- gathering remaining instances"
                );
                // wait for a little while for the cancelled spot requests to settle
                // and any that were *just* made active to be associated with their instances
                thread::sleep(time::Duration::from_secs(1));

                let sirs = client
                    .describe_spot_instance_requests(req)
                    .await?
                    .spot_instance_requests
                    .unwrap_or_else(Vec::new);
                for sir in sirs {
                    match sir.instance_id {
                        Some(instance_id) => {
                            trace!(log, "spot request cancelled";
                                "req_id" => sir.spot_instance_request_id,
                                "iid" => &instance_id,
                            );
                        }
                        _ => {
                            error!(
                                log,
                                "spot request failed: {:?}", &sir.status;
                                "req_id" => sir.spot_instance_request_id,
                            );
                        }
                    }
                }
                bail!("wait limit reached");
            }
        }

        Ok(())
    }

    /// Poll AWS until `max_wait` (if not `None`) or the instances are ready to SSH to.
    async fn wait_for_instances(&mut self, max_wait: Option<time::Duration>) -> Result<(), Error> {
        let start = time::Instant::now();
        let mut desc_req = rusoto_ec2::DescribeInstancesRequest::default();
        let client = self.client.as_ref().unwrap();
        let log = self.log.as_ref().unwrap();
        let private_key_path = self.private_key_path.as_ref().unwrap();
        let mut all_ready = self.instances.is_empty();
        desc_req.instance_ids = Some(self.instances.keys().cloned().collect());
        while !all_ready {
            all_ready = true;

            for reservation in client
                .describe_instances(desc_req.clone())
                .await
                .context("Could not query AWS for instance state")?
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
                            trace!(log, "instance running";
                                "instance_id" => instance_id.clone(),
                                "ip" => &public_ip,
                            );

                            // try connecting. If can't, not ready.
                            let tag_setup = self.instances.get_mut(&instance_id).unwrap();

                            let mut m = crate::Machine {
                                nickname: Default::default(),
                                public_dns: Default::default(),
                                public_ip: public_ip.to_string(),
                                private_ip: None,
                                ssh: None,
                                _tsunami: Default::default(),
                            };

                            if let Err(e) = m
                                .connect_ssh(
                                    log,
                                    &tag_setup.setup.username,
                                    Some(private_key_path.path()),
                                    max_wait,
                                    22,
                                )
                                .await
                            {
                                trace!(log, "ssh failed"; "instance_id" => instance_id.clone(), "ip" => &public_ip, "err" => ?e);
                                all_ready = false;
                            } else {
                                debug!(log, "instance ready";
                                    "instance_id" => instance_id.clone(),
                                    "ip" => &public_ip,
                                );

                                tag_setup.ip_info = Some(IpInfo {
                                    public_ip: public_ip.clone(),
                                    public_dns: public_dns.clone(),
                                    private_ip: private_ip.clone(),
                                });
                            }
                        }
                        _ => {
                            all_ready = false;
                        }
                    }
                }
            }

            if let Some(to) = max_wait {
                if time::Instant::now().duration_since(start) > to {
                    bail!("timed out");
                }
            }
        }

        futures_util::future::join_all(self.instances.iter().map(
            |(
                _instance_id,
                TaggedSetup {
                    ip_info,
                    name,
                    setup,
                },
            )| {
                async move {
                    let IpInfo { public_ip, .. } = ip_info.as_ref().unwrap();
                    if let Setup {
                        username,
                        setup_fn: Some(f),
                        ..
                    } = setup
                    {
                        super::setup_machine(
                            log,
                            &name,
                            &public_ip,
                            &username,
                            max_wait,
                            Some(private_key_path.path()),
                            f.as_ref(),
                        )
                        .await?;
                    }

                    Ok(())
                }
            },
        ))
        .await
        .into_iter()
        .collect()
    }

    /// Establish SSH connections to the machines. The `Ok` value is a `HashMap` associating the
    /// friendly name for each `Setup` with the corresponding SSH connection.
    pub async fn connect_all<'l>(&'l self) -> Result<HashMap<String, crate::Machine<'l>>, Error> {
        let log = self.log.as_ref().unwrap();
        let private_key_path = self.private_key_path.as_ref().unwrap();
        futures_util::future::join_all(self.instances.values().map(|info| async move {
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
                    let mut m = Machine {
                        public_ip: public_ip.clone(),
                        public_dns: public_dns.clone(),
                        private_ip: Some(private_ip.clone()),
                        nickname: name.clone(),
                        ssh: None,
                        _tsunami: Default::default(),
                    };

                    m.connect_ssh(log, &username, Some(private_key_path.path()), None, 22)
                        .await?;
                    Ok((name.clone(), m))
                }
                _ => bail!("Machines not initialized"),
            }
        }))
        .await
        .into_iter()
        .collect()
    }

    /// Terminate all running instances.
    ///
    /// Additionally deletes ephemeral keys and security groups. Note: it is a known issue that
    /// security groups often will not be deleted, due to timing quirks in the AWS api.
    pub async fn shutdown(&mut self) {
        let client = self.client.as_ref().unwrap();
        let log = self.log.as_ref().expect("RegionLauncher uninitialized");
        // terminate instances
        if !self.instances.is_empty() {
            info!(log, "terminating instances");
            let instances = self.instances.keys().cloned().collect();
            self.instances.clear();
            let mut termination_req = rusoto_ec2::TerminateInstancesRequest::default();
            termination_req.instance_ids = instances;
            while let Err(e) = client.terminate_instances(termination_req.clone()).await {
                let msg = format!("{}", e);
                if msg.contains("Pooled stream disconnected") || msg.contains("broken pipe") {
                    trace!(log, "retrying instance termination");
                    continue;
                } else {
                    warn!(log, "failed to terminate tsunami instances: {:?}", e);
                    break;
                }
            }
        }

        debug!(log, "cleaning up temporary resources");
        if !self.security_group_id.trim().is_empty() {
            trace!(log, "cleaning up temporary security group"; "name" => self.security_group_id.clone());
            // clean up security groups and keys
            // TODO need a retry loop for the security group. Currently, this fails
            // because AWS takes some time to allow the security group to be deleted.
            let mut req = rusoto_ec2::DeleteSecurityGroupRequest::default();
            req.group_id = Some(self.security_group_id.clone());
            if let Err(e) = client.delete_security_group(req).await {
                warn!(log, "failed to clean up temporary security group";
                    "group_id" => &self.security_group_id,
                    "error" => ?e,
                )
            }
        }

        if !self.ssh_key_name.trim().is_empty() {
            trace!(log, "cleaning up temporary keypair"; "name" => self.ssh_key_name.clone());
            let mut req = rusoto_ec2::DeleteKeyPairRequest::default();
            req.key_name = self.ssh_key_name.clone();
            if let Err(e) = client.delete_key_pair(req).await {
                warn!(log, "failed to clean up temporary SSH key";
                    "key_name" => &self.ssh_key_name,
                    "error" => ?e,
                )
            }
        }
    }
}

struct UbuntuAmi(String);

impl From<Region> for UbuntuAmi {
    fn from(r: Region) -> Self {
        // https://cloud-images.ubuntu.com/locator/
        // ec2 20190814 releases
        UbuntuAmi(
            match r {
                Region::ApEast1 => "ami-e0ff8491",               // Hong Kong
                Region::ApNortheast1 => "ami-0cb1c8cab7f5249b6", // Tokyo
                Region::ApNortheast2 => "ami-081626bfb3fbc9f49", // Seoul
                Region::ApSouth1 => "ami-0cf8402efdb171312",     // Mumbai
                Region::ApSoutheast1 => "ami-099d318f80eab7e94", // Singapore
                Region::ApSoutheast2 => "ami-08a648fb5cc86fb74", // Sydney
                Region::CaCentral1 => "ami-0bc1dd4eb012a451e",   // Canada
                Region::EuCentral1 => "ami-0cdab515472ca0bac",   // Frankfurt
                Region::EuNorth1 => "ami-c37bf0bd",              // Stockholm
                Region::EuWest1 => "ami-01cca82393e531118",      // Ireland
                Region::EuWest2 => "ami-0a7c91b6616d113b1",      // London
                Region::EuWest3 => "ami-033e0056c336ecff0",      // Paris
                Region::SaEast1 => "ami-094c359b4d8c6a8ca",      // Sao Paulo
                Region::UsEast1 => "ami-064a0193585662d74",      // N Virginia
                Region::UsEast2 => "ami-021b7b04f1ac696c2",      // Ohio
                Region::UsWest1 => "ami-056d04da775d124d7",      // N California
                Region::UsWest2 => "ami-09a3d8a7177216dcf",      // Oregon
                x => panic!("Unsupported Region {:?}", x),
            }
            .into(),
        )
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
    use crate::test::test_logger;
    use failure::{Error, ResultExt};
    use rusoto_core::credential::DefaultCredentialsProvider;
    use rusoto_core::region::Region;
    use rusoto_ec2::Ec2;
    use std::future::Future;

    fn do_make_machine_and_ssh_setupfn<'l>(
        l: &'l mut super::Launcher,
    ) -> impl Future<Output = Result<(), Error>> + 'l {
        use crate::providers::Launcher;
        async move {
            l.spawn(
                vec![(
                    String::from("my machine"),
                    super::Setup::default().setup(|ssh, _| {
                        Box::pin(async move {
                            if ssh.command("whoami").status().await?.success() {
                                Ok(())
                            } else {
                                Err(failure::format_err!("failed"))
                            }
                        })
                    }),
                )],
                None,
                None,
            )
            .await?;
            let vms = l.connect_all().await?;
            let my_machine = vms
                .get("my machine")
                .ok_or_else(|| failure::format_err!("machine not found"))?;
            my_machine
                .ssh
                .as_ref()
                .unwrap()
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
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        let mut l = super::Launcher::default();
        // make the defined-duration instances expire after 1 hour
        l.set_max_instance_duration(1);
        rt.block_on(async move {
            if let Err(e) = do_make_machine_and_ssh_setupfn(&mut l).await {
                // failed test.
                l.cleanup().await.unwrap();
                panic!(e);
            } else {
                l.cleanup().await.unwrap();
            }
        })
    }

    #[test]
    #[ignore]
    fn make_key() -> Result<(), Error> {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        let region = Region::UsEast1;
        let provider = DefaultCredentialsProvider::new()?;
        let ec2 = RegionLauncher::connect(
            region,
            super::AvailabilityZoneSpec::Any,
            provider,
            test_logger(),
        )?;
        rt.block_on(async {
            let mut ec2 = ec2.make_ssh_key().await?;
            println!("==> key name: {}", ec2.ssh_key_name);
            println!("==> key path: {:?}", ec2.private_key_path);
            assert!(!ec2.ssh_key_name.is_empty());
            assert!(ec2.private_key_path.as_ref().unwrap().path().exists());

            let mut req = rusoto_ec2::DeleteKeyPairRequest::default();
            req.key_name = ec2.ssh_key_name.clone();
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
        logger: slog::Logger,
    ) -> impl Future<Output = Result<(), Error>> + 'l {
        async move {
            use super::Setup;

            let names = (1..).map(|x| format!("{}", x));
            let setup = Setup::default();
            let ms: Vec<(String, Setup)> = names.zip(itertools::repeat_n(setup, 5)).collect();

            debug!(&logger, "make spot instance requests"; "num" => ms.len());
            ec2.make_spot_instance_requests(60 as _, ms).await?;
            assert_eq!(ec2.outstanding_spot_request_ids.len(), 5);
            debug!(&logger, "wait for spot instance requests");
            ec2.wait_for_spot_instance_requests(None).await?;

            Ok(())
        }
    }

    #[test]
    #[ignore]
    fn multi_instance_spot_request() -> Result<(), Error> {
        let region = "us-east-1";
        let provider = DefaultCredentialsProvider::new()?;
        let logger = test_logger();

        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut ec2 = RegionLauncher::new(
                region,
                super::AvailabilityZoneSpec::Any,
                provider,
                false,
                logger.clone(),
            )
            .await?;

            if let Err(e) = do_multi_instance_spot_request(&mut ec2, logger).await {
                ec2.shutdown().await;
                panic!(e);
            } else {
                ec2.shutdown().await;
            }

            Ok(())
        })
    }
}
