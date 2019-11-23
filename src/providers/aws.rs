//! AWS backend for tsunami.
//!
//! The primary `impl Launcher` type is [`Launcher`].
//! It internally uses the lower-level, region-specific [`aws::RegionLauncher`].
//! Both these types use [`aws::Setup`] as their descriptor type.
//!
//! This implementation uses [defined duration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-requests.html#fixed-duration-spot-instances)
//! instances.
//!
//! # Example
//! ```rust,no_run
//! use tsunami::providers::{aws, Launcher};
//! use tsunami::TsunamiBuilder;
//!
//! let mut b = TsunamiBuilder::default();
//! b.add("my machine", aws::Setup::default()).unwrap();
//! let mut l = aws::Launcher::default();
//! // make the defined-duration instances expire after 1 hour
//! l.set_max_instance_duration(1);
//! b.spawn(&mut l).unwrap();
//! let vms = l.connect_all().unwrap();
//! let my_machine = vms.get("my machine").unwrap();
//! let (stdout, stderr) = my_machine.ssh.as_ref().unwrap().cmd("echo \"Hello, EC2\"").unwrap();
//! println!("{}", stdout);
//! ```
//! ```rust,no_run
//! use tsunami::TsunamiBuilder;
//! use tsunami::providers::{Launcher, aws};
//! use rusoto_core::{DefaultCredentialsProvider, Region};
//! fn main() -> Result<(), failure::Error> {
//!     // Initialize AWS
//!     let mut aws = aws::Launcher::default();
//!     // make the defined-duration instances expire after 1 hour
//!     // default is the maximum (6 hours)
//!     aws.set_max_instance_duration(1);
//!
//!     // Initialize a TsunamiBuilder
//!     let mut tb = TsunamiBuilder::default();
//!     tb.use_term_logger();
//!
//!     // Create a machine descriptor and add it to the Tsunami
//!     let m = aws::Setup::default()
//!         .region_with_ubuntu_ami(Region::UsWest1) // default is UsEast1
//!         .setup(|ssh, _| { // default is a no-op
//!             ssh.cmd("sudo apt update")?;
//!             ssh.cmd("curl https://sh.rustup.rs -sSf | sh -- -y")?;
//!             Ok(())
//!         });
//!     tb.add("my_vm", m);
//!
//!     // Launch the VM
//!     tb.spawn(&mut aws)?;
//!
//!     // SSH to the VM and run a command on it
//!     let vms = aws.connect_all()?;
//!     let my_vm = vms.get("my_vm").unwrap();
//!     println!("public ip: {}", my_vm.public_ip);
//!     let ssh = my_vm.ssh.as_ref().unwrap();
//!     ssh.cmd("git clone https://github.com/jonhoo/tsunami")?;
//!     ssh.cmd("cd tsunami && cargo build")?;
//!     Ok(())
//! }
//! ```

use crate::ssh;
use crate::Machine;
use educe::Educe;
use failure::{Error, ResultExt};
use itertools::Itertools;
use rusoto_core::request::HttpClient;
use rusoto_core::{DefaultCredentialsProvider, ProvideAwsCredentials, Region};
use rusoto_ec2::Ec2;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::{thread, time};

/// Marker type for [`Setup`] indicating that it does not have the given field.
#[derive(Clone, Copy, Debug)]
pub struct No;
/// Marker type for [`Setup`] indicating that it has the given field.
#[derive(Clone, Copy, Debug)]
pub struct Yes;

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
pub struct Setup<HasAmi = Yes, HasUsername = Yes> {
    region: Region,
    instance_type: String,
    ami: Option<String>,
    username: String,
    #[educe(Debug(ignore))]
    setup: Option<Arc<dyn Fn(&mut ssh::Session, &slog::Logger) -> Result<(), Error> + Send + Sync>>,
    _phantom: std::marker::PhantomData<(HasAmi, HasUsername)>,
}

impl super::MachineSetup for Setup<Yes, Yes> {
    type Region = String;

    fn region(&self) -> Self::Region {
        self.region.name().to_string()
    }
}

impl Default for Setup<Yes, Yes> {
    fn default() -> Self {
        Setup {
            region: Region::UsEast1,
            instance_type: "t3.small".into(),
            ami: Some(UbuntuAmi::from(Region::UsEast1).into()),
            username: "ubuntu".into(),
            setup: None,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<A, B> Setup<A, B> {
    /// Set up the machine in a specific EC2
    /// [`Region`](http://rusoto.github.io/rusoto/rusoto_core/region/enum.Region.html).
    ///
    /// The default region is us-east-1. [Available regions are listed
    /// here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions)
    ///
    /// AMIs are region-specific. This will overwrite the ami field to
    /// the Ubuntu 18.04 LTS AMI in the selected region.
    pub fn region_with_ubuntu_ami(mut self, region: Region) -> Setup<Yes, Yes> {
        self.region = region.clone();
        let ami: String = UbuntuAmi::from(region).into();
        self.ami(ami).username("ubuntu")
    }

    /// The new instance will start out in the state dictated by the Amazon Machine Image specified
    /// in `ami`. Default is Ubuntu 18.04 LTS.
    pub fn ami(self, ami: impl ToString) -> Setup<Yes, No> {
        Setup {
            region: self.region,
            instance_type: self.instance_type,
            ami: Some(ami.to_string()),
            username: "".to_string(),
            setup: self.setup,
            _phantom: std::marker::PhantomData,
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
    ///     .setup(|ssh, log| {
    ///         slog::info!(log, "running setup!");
    ///         ssh.cmd("sudo apt update")?;
    ///         Ok(())
    ///     });
    /// ```
    pub fn setup(
        mut self,
        setup: impl Fn(&mut ssh::Session, &slog::Logger) -> Result<(), Error> + Send + Sync + 'static,
    ) -> Self {
        self.setup = Some(Arc::new(setup));
        self
    }

    /// Set up the machine in a specific EC2
    /// [`Region`](http://rusoto.github.io/rusoto/rusoto_core/region/enum.Region.html).
    ///
    /// The default region is us-east-1. [Available regions are listed
    /// here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions)
    ///
    /// AMIs are region-specific.
    /// This will clear the AMI field, which must be set for this struct to be useful.
    pub fn region(self, region: Region) -> Setup<No, No> {
        Setup {
            region,
            instance_type: self.instance_type,
            ami: None,
            username: "".into(),
            setup: self.setup,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<A> Setup<Yes, A> {
    /// Set the username used to ssh into the machine.
    ///
    /// If the user sets a custom AMI, they must call this method to
    /// set a username.
    pub fn username(self, username: impl ToString) -> Setup<Yes, Yes> {
        Setup {
            region: self.region,
            instance_type: self.instance_type,
            ami: self.ami,
            username: username.to_string(),
            setup: self.setup,
            _phantom: std::marker::PhantomData,
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

impl<P> Launcher<P>
where
    P: ProvideAwsCredentials + Send + Sync + 'static,
    <P as ProvideAwsCredentials>::Future: Send,
{
    fn get_credential_provider(&self) -> Result<P, Error> {
        (*self.credential_provider)()
    }
}

impl<P> super::Launcher for Launcher<P>
where
    P: ProvideAwsCredentials + Send + Sync + 'static,
    <P as ProvideAwsCredentials>::Future: Send,
{
    type MachineDescriptor = Setup;

    fn launch(&mut self, l: super::LaunchDescriptor<Self::MachineDescriptor>) -> Result<(), Error> {
        let prov = self.get_credential_provider()?;
        let mut awsregion =
            RegionLauncher::new(&l.region.to_string(), prov, self.use_open_ports, l.log)?;
        awsregion.launch(self.max_instance_duration_hours, l.max_wait, l.machines)?;
        self.regions.insert(l.region, awsregion);
        Ok(())
    }

    fn connect_all<'l>(&'l self) -> Result<HashMap<String, crate::Machine<'l>>, Error> {
        collect!(self.regions)
    }
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
/// If this is dropped before the duration is over, the instances will be terminated.
#[derive(Educe, Default)]
#[educe(Debug)]
pub struct RegionLauncher {
    /// The region this RegionLauncher is connected to.
    pub region: rusoto_core::region::Region,
    security_group_id: String,
    ssh_key_name: String,
    private_key_path: Option<tempfile::NamedTempFile>,
    #[educe(Debug(ignore))]
    client: Option<rusoto_ec2::Ec2Client>,
    outstanding_spot_request_ids: HashMap<String, (String, Setup)>,
    instances: HashMap<String, (Option<(String, String)>, (String, Setup))>,
    log: Option<slog::Logger>,
}

impl RegionLauncher {
    /// Connect to AWS region `region`, using credentials provider `provider`.
    ///
    /// This is a lower-level API, you may want [`Launcher`] instead.
    ///
    /// This will create a temporary security group and SSH key in the given AWS region.
    pub fn new<P>(
        region: &str,
        provider: P,
        use_open_ports: bool,
        log: slog::Logger,
    ) -> Result<Self, Error>
    where
        P: ProvideAwsCredentials + Send + Sync + 'static,
        <P as ProvideAwsCredentials>::Future: Send,
    {
        let region = region.parse()?;
        let ec2 = RegionLauncher::connect(region, provider, log)?
            .make_security_group(use_open_ports)?
            .make_ssh_key()?;

        Ok(ec2)
    }

    fn connect<P>(
        region: rusoto_core::region::Region,
        provider: P,
        log: slog::Logger,
    ) -> Result<Self, Error>
    where
        P: ProvideAwsCredentials + Send + Sync + 'static,
        <P as ProvideAwsCredentials>::Future: Send,
    {
        debug!(log, "connecting to ec2");
        let ec2 = rusoto_ec2::Ec2Client::new_with(HttpClient::new()?, provider, region.clone());

        Ok(Self {
            region,
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
    pub fn launch(
        &mut self,
        max_instance_duration_hours: usize,
        max_wait: Option<time::Duration>,
        machines: impl IntoIterator<Item = (String, Setup)>,
    ) -> Result<(), Error> {
        self.make_spot_instance_requests(
            max_instance_duration_hours * 60, // 60 mins/hr
            machines,
        )?;

        let start = time::Instant::now();
        self.wait_for_spot_instance_requests(max_wait)?;
        if let Some(mut d) = max_wait {
            d -= time::Instant::now().duration_since(start);
        }

        self.wait_for_instances(max_wait)?;
        Ok(())
    }

    fn make_security_group(mut self, use_open_ports: bool) -> Result<Self, Error> {
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
            .sync()
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
            .sync()
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
            .sync()
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
            .sync()
            .context("failed to fill in security group for new machines")?;

        self.security_group_id = group_id;
        Ok(self)
    }

    fn make_ssh_key(mut self) -> Result<Self, Error> {
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
            .sync()
            .context("failed to generate new key pair")?;
        trace!(log, "created keypair"; "fingerprint" => res.key_fingerprint);

        // write keypair to disk
        let private_key = res
            .key_material
            .expect("aws did not generate key material for new key");
        private_key_path
            .write_all(private_key.as_bytes())
            .context("could not write private key to file")?;
        trace!(log, "wrote keypair to file"; "filename" => private_key_path.path().display());

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
    fn make_spot_instance_requests(
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
                (
                    (m.ami.as_ref().unwrap().clone(), m.instance_type.clone()),
                    (name, m),
                )
            })
            .into_group_map()
        // group by the labels
        {
            // and issue one spot request per group
            let mut launch = rusoto_ec2::RequestSpotLaunchSpecification::default();
            launch.image_id = Some(reqs[0].1.ami.as_ref().unwrap().clone());
            launch.instance_type = Some(reqs[0].1.instance_type.clone());
            launch.placement = None;

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
                .sync()
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
                self.outstanding_spot_request_ids.insert(sir, req);
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
    fn wait_for_spot_instance_requests(
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

            let res = client.describe_spot_instance_requests(req.clone()).sync();
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

                            Some((instance_id, (None, self.outstanding_spot_request_ids.remove(&sir.spot_instance_request_id.unwrap()).unwrap())))
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
                    .sync()
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
                    .sync()?
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
    fn wait_for_instances(&mut self, max_wait: Option<time::Duration>) -> Result<(), Error> {
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
                .sync()
                .context("failed to cancel spot instances")?
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
                            ..
                        } => {
                            trace!(log, "instance ready";
                                "instance_id" => instance_id.clone(),
                                "ip" => &public_ip,
                            );

                            let (ipinfo, _) = self.instances.get_mut(&instance_id).unwrap();
                            *ipinfo = Some((public_ip.clone(), public_dns.clone()));
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

        use rayon::prelude::*;
        self.instances
            .par_iter()
            .try_for_each(|(_instance_id, (ipinfo, (name, m_setup)))| {
                let (public_ip, _) = ipinfo.as_ref().unwrap();
                if let Setup {
                    username,
                    setup: Some(f),
                    ..
                } = m_setup
                {
                    super::setup_machine(
                        log,
                        &name,
                        &public_ip,
                        &username,
                        max_wait,
                        Some(private_key_path.path()),
                        f.as_ref(),
                    )?;
                }

                Ok(())
            })
    }

    /// Establish SSH connections to the machines. The `Ok` value is a `HashMap` associating the
    /// friendly name for each `Setup` with the corresponding SSH connection.
    pub fn connect_all<'l>(&'l self) -> Result<HashMap<String, crate::Machine<'l>>, Error> {
        let log = self.log.as_ref().unwrap();
        let private_key_path = self.private_key_path.as_ref().unwrap();
        self.instances
            .values()
            .map(|info| match info {
                (Some((public_ip, public_dns)), (name, Setup { username, .. })) => {
                    let mut m = Machine {
                        public_ip: public_ip.clone(),
                        public_dns: public_dns.clone(),
                        nickname: name.clone(),
                        ssh: None,
                        _tsunami: Default::default(),
                    };

                    m.connect_ssh(log, &username, Some(private_key_path.path()))?;
                    Ok((name.clone(), m))
                }
                _ => bail!("Machines not initialized"),
            })
            .collect()
    }
}

impl Drop for RegionLauncher {
    fn drop(&mut self) {
        let client = self.client.as_ref().unwrap();
        let log = self.log.as_ref().expect("RegionLauncher uninitialized");
        // terminate instances
        if !self.instances.is_empty() {
            info!(log, "terminating instances");
            let instances = self.instances.keys().cloned().collect();
            self.instances.clear();
            let mut termination_req = rusoto_ec2::TerminateInstancesRequest::default();
            termination_req.instance_ids = instances;
            while let Err(e) = client.terminate_instances(termination_req.clone()).sync() {
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
            if let Err(e) = client.delete_security_group(req).sync() {
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
            if let Err(e) = client.delete_key_pair(req).sync() {
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
    use rusoto_core::region::Region;
    use rusoto_core::DefaultCredentialsProvider;
    use rusoto_ec2::Ec2;

    #[test]
    #[ignore]
    fn make_key() -> Result<(), Error> {
        let region = Region::UsEast1;
        let provider = DefaultCredentialsProvider::new()?;
        let ec2 = RegionLauncher::connect(region, provider, test_logger())?;

        let mut ec2 = ec2.make_ssh_key()?;
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
            .sync()
            .context(format!(
                "Could not delete ssh key pair {:?}",
                ec2.ssh_key_name
            ))?;

        Ok(())
    }

    #[test]
    #[ignore]
    fn multi_instance_spot_request() -> Result<(), Error> {
        let region = "us-east-1";
        let provider = DefaultCredentialsProvider::new()?;
        let logger = test_logger();
        let mut ec2 = RegionLauncher::new(region, provider, false, logger.clone())?;

        use super::Setup;

        let names = (1..).map(|x| format!("{}", x));
        let setup = Setup::default();
        let ms: Vec<(String, Setup)> = names.zip(itertools::repeat_n(setup, 5)).collect();

        debug!(&logger, "make spot instance requests"; "num" => ms.len());
        ec2.make_spot_instance_requests(60, ms)?;
        assert_eq!(ec2.outstanding_spot_request_ids.len(), 5);
        debug!(&logger, "wait for spot instance requests");
        ec2.wait_for_spot_instance_requests(None)?;
        Ok(())
    }
}
