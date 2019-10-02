use crate::ssh;
use crate::Machine;
use failure::{Error, ResultExt};
use rusoto_core::request::HttpClient;
use rusoto_core::{ProvideAwsCredentials, Region};
use rusoto_ec2::Ec2;
use std::collections::HashMap;
use std::io::Write;
use std::{thread, time};

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

/// A descriptor for a particular machine setup in a tsunami.
///
/// The `setup` argument is called once for every spawned instances of this type with a handle
/// to the target machine. Use [`Machine::ssh`](struct.Machine.html#structfield.ssh) to issue
/// commands on the host in question.
pub struct MachineSetup {
    region: Region,
    instance_type: String,
    ami: String,
    setup: Option<Box<dyn Fn(&mut ssh::Session, &slog::Logger) -> Result<(), Error> + Send + Sync>>,
}

impl super::MachineSetup for MachineSetup {
    type Region = String;

    fn region(&self) -> Self::Region {
        self.region.name().to_string()
    }
}

impl PartialEq for MachineSetup {
    fn eq(&self, other: &Self) -> bool {
        self.ami == other.ami && self.instance_type == other.instance_type
    }
}

impl Eq for MachineSetup {}

impl std::hash::Hash for MachineSetup {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.instance_type.hash(state);
        self.ami.hash(state);
    }
}

impl Default for MachineSetup {
    fn default() -> Self {
        MachineSetup {
            region: Region::UsEast1,
            instance_type: "t3.small".into(),
            ami: UbuntuAmi::from(Region::UsEast1).into(),
            setup: None,
        }
    }
}

impl MachineSetup {
    /// Set up the machine in a specific EC2
    /// [`Region`](http://rusoto.github.io/rusoto/rusoto_core/region/enum.Region.html).
    ///
    /// The default region is us-east-1. [Available regions are listed
    /// here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions)
    /// AMIs are region-specific. This will overwrite the ami field to
    /// the Ubuntu 18.04 LTS AMI in the selected region.
    pub fn region(mut self, region: Region) -> Self {
        self.region = region.clone();
        self.ami = UbuntuAmi::from(region).into();
        self
    }

    /// The given AWS EC2 instance type will be used. Note that only [EC2 Defined Duration Spot
    /// Instance types](https://aws.amazon.com/ec2/spot/pricing/) are allowed.
    pub fn instance_type(mut self, typ: impl std::string::ToString) -> Self {
        self.instance_type = typ.to_string();
        self
    }

    /// The new instance will start out in the state dictated by the Amazon Machine Image specified
    /// in `ami`. Default is Ubuntu 18.04 LTS.
    pub fn ami(mut self, ami: impl std::string::ToString) -> Self {
        self.ami = ami.to_string();
        self
    }

    /// The `setup` argument is called once for every spawned instances of this type with a handle
    /// to the target machine. Use [`Machine::ssh`](struct.Machine.html#structfield.ssh) to issue
    /// commands on the host in question.
    pub fn setup(
        mut self,
        setup: impl Fn(&mut ssh::Session, &slog::Logger) -> Result<(), Error> + Send + Sync + 'static,
    ) -> Self {
        self.setup = Some(Box::new(setup));
        self
    }
}

/// Launch AWS EC2 spot instances.
///
/// This implementation uses [rusoto](https://crates.io/crates/rusoto_core) to connect to AWS.
/// Therefore, you must call [`with_credentials`](AWSLauncher::with_credentials) to authenticate
/// with AWS.
/// Each individual region is handled by `AWSRegion`.
pub struct AWSLauncher<P: ProvideAwsCredentials> {
    credential_provider: Option<Box<dyn Fn() -> Result<P, Error>>>,
    max_instance_duration: Option<std::time::Duration>,
    regions: HashMap<<MachineSetup as super::MachineSetup>::Region, AWSRegion>,
}

impl<P: ProvideAwsCredentials> Default for AWSLauncher<P> {
    fn default() -> Self {
        AWSLauncher {
            credential_provider: None,
            max_instance_duration: None,
            regions: Default::default(),
        }
    }
}

impl<P> AWSLauncher<P>
where
    P: ProvideAwsCredentials + Send + Sync + 'static,
    <P as ProvideAwsCredentials>::Future: Send,
{
    /// A closure which returns [`P:
    /// ProvideAwsCredentials`](https://docs.rs/rusoto_core/0.40.0/rusoto_core/trait.ProvideAwsCredentials.html).
    ///
    /// For example to specify using
    /// [`DefaultCredentialsProvider`](https://docs.rs/rusoto_core/0.40.0/rusoto_core/struct.DefaultCredentialsProvider.html):
    /// ```rust
    /// use rusoto_core::DefaultCredentialsProvider;
    /// let mut l: tsunami::providers::aws::AWSLauncher<_> = Default::default();
    /// l.with_credentials(|| Ok(DefaultCredentialsProvider::new()?));
    /// ```
    pub fn with_credentials(&mut self, f: impl Fn() -> Result<P, Error> + 'static) -> &mut Self {
        self.credential_provider = Some(Box::new(f));
        self
    }

    /// `AWSLauncher` uses [defined duration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-requests.html#fixed-duration-spot-instances)
    /// instances.
    ///
    /// The lifetime of such instances must be declared in advance (1-6 hours). By default, we use 6 hours (the
    /// maximum). If `t` > 6 hours, `AWSLauncher` will use a duration of 6 hours.
    pub fn set_max_instance_duration(&mut self, t: std::time::Duration) -> &mut Self {
        self.max_instance_duration = Some(t);
        self
    }

    // TODO with rust specialization (https://github.com/rust-lang/rust/issues/31844), can do:
    // ```
    // self.credential_provider.unwrap_or_else(|| Box::new(|| DefaultCredentialProvider::new()))?()
    // ```
    fn get_credential_provider(&self) -> Result<P, Error> {
        self.credential_provider
            .as_ref()
            .ok_or_else(|| format_err!("No credential provider given"))?()
    }
}

impl<P> super::Launcher for AWSLauncher<P>
where
    P: ProvideAwsCredentials + Send + Sync + 'static,
    <P as ProvideAwsCredentials>::Future: Send,
{
    type Machine = MachineSetup;

    fn launch(&mut self, l: super::LaunchDescriptor<Self::Machine>) -> Result<(), Error> {
        let prov = self.get_credential_provider()?;
        let mut awsregion = AWSRegion::new(&l.region.to_string(), prov, l.log)?;
        awsregion.make_spot_instance_requests(
            self.max_instance_duration
                .map(|x| (std::cmp::min(360, x.as_secs() / 60)) as i64)
                .unwrap_or_else(|| 360),
            l.machines,
        )?;

        let start = time::Instant::now();
        awsregion.wait_for_spot_instance_requests(l.max_wait)?;
        if let Some(mut d) = l.max_wait {
            d -= time::Instant::now().duration_since(start);
        }

        awsregion.wait_for_instances(l.max_wait)?;
        self.regions.insert(l.region, awsregion);
        Ok(())
    }

    fn connect_all<'l>(&'l self) -> Result<HashMap<String, crate::Machine<'l>>, Error> {
        collect!(self.regions)
    }
}

impl<P: ProvideAwsCredentials> std::ops::Drop for AWSLauncher<P> {
    fn drop(&mut self) {}
}

/// Region specific. Launch AWS EC2 spot instances.
///
/// This implementation uses [rusoto](https://crates.io/crates/rusoto_core) to connect to AWS.
///
/// EC2 spot instances are normally subject to termination at any point. This library instead
/// uses [defined duration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-requests.html#fixed-duration-spot-instances)
/// instances, which cost slightly more, but are never prematurely terminated.  The lifetime of
/// such instances must be declared in advance (1-6 hours). By default, we use 6 hours (the
/// maximum). To change this, AWSRegion respects the limit specified in
/// [`AWSLauncher::set_max_instance_duration`](AWSLauncher::set_max_instance_duration).
#[derive(Default)]
pub struct AWSRegion {
    pub region: rusoto_core::region::Region,
    security_group_id: String,
    ssh_key_name: String,
    private_key_path: Option<tempfile::NamedTempFile>,
    client: Option<rusoto_ec2::Ec2Client>,
    outstanding_spot_request_ids: HashMap<String, (String, MachineSetup)>,
    instances: HashMap<String, (Option<(String, String)>, (String, MachineSetup))>,
    log: Option<slog::Logger>,
}

impl AWSRegion {
    /// Connect to AWS region `region`, using credentials provider `provider`.
    pub fn new<P>(region: &str, provider: P, log: slog::Logger) -> Result<Self, Error>
    where
        P: ProvideAwsCredentials + Send + Sync + 'static,
        <P as ProvideAwsCredentials>::Future: Send,
    {
        let region = region.parse()?;
        let ec2 = AWSRegion::connect(region, provider, log)?
            .make_security_group()?
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

    fn make_security_group(mut self) -> Result<Self, Error> {
        let log = self.log.as_ref().expect("AWSRegion uninitialized");
        let ec2 = self.client.as_mut().expect("AWSRegion unconnected");

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

        // cross-VM talk
        req.ip_protocol = Some("tcp".to_string());
        req.from_port = Some(0);
        req.to_port = Some(65535);
        req.cidr_ip = Some("0.0.0.0/0".to_string());
        trace!(log, "adding internal VM access to security group");
        ec2.authorize_security_group_ingress(req.clone())
            .sync()
            .context("failed to fill in security group for new machines")?;

        req.ip_protocol = Some("udp".to_string());
        req.from_port = Some(0);
        req.to_port = Some(65535);
        req.cidr_ip = Some("0.0.0.0/0".to_string());
        trace!(log, "adding internal VM access to security group");
        ec2.authorize_security_group_ingress(req)
            .sync()
            .context("failed to fill in security group for new machines")?;

        self.security_group_id = group_id;
        Ok(self)
    }

    fn make_ssh_key(mut self) -> Result<Self, Error> {
        let log = self.log.as_ref().expect("AWSRegion uninitialized");
        let ec2 = self.client.as_mut().expect("AWSRegion unconnected");
        let private_key_path = self
            .private_key_path
            .as_mut()
            .expect("AWSRegion unconnected");

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

    /// `max_duration` is in minutes.
    pub fn make_spot_instance_requests(
        &mut self,
        max_duration: i64,
        machines: impl IntoIterator<Item = (String, MachineSetup)>,
    ) -> Result<(), Error> {
        let log = self.log.as_ref().expect("AWSRegion uninitialized");
        for (name, m) in machines {
            let mut launch = rusoto_ec2::RequestSpotLaunchSpecification::default();
            launch.image_id = Some(m.ami.clone());
            launch.instance_type = Some(m.instance_type.clone());
            launch.placement = None;

            launch.security_group_ids = Some(vec![self.security_group_id.clone()]);
            launch.key_name = Some(self.ssh_key_name.clone());

            // TODO: VPC

            let req = rusoto_ec2::RequestSpotInstancesRequest {
                instance_count: Some(1),
                block_duration_minutes: Some(max_duration),
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
            let spot_req_id = res
                .spot_instance_requests
                .expect("request_spot_instances should always return spot instance requests")
                .into_iter()
                .filter_map(|sir| sir.spot_instance_request_id)
                .map(|sir| {
                    // TODO: add more info if in parallel
                    trace!(l, "activated spot request"; "id" => &sir);
                    sir
                })
                .next()
                .ok_or_else(|| failure::format_err!("a"))?;
            self.outstanding_spot_request_ids
                .insert(spot_req_id.clone(), (name, m));
        }

        Ok(())
    }

    pub fn wait_for_spot_instance_requests(
        &mut self,
        max_wait: Option<time::Duration>,
    ) -> Result<(), Error> {
        let log = { self.log.as_ref().expect("AWSRegion uninitialized").clone() };
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
                if start.elapsed() > wait_limit {
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
        }

        Ok(())
    }

    pub fn wait_for_instances(&mut self, max_wait: Option<time::Duration>) -> Result<(), Error> {
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
                            use std::net::{IpAddr, SocketAddr};
                            let mut sess = ssh::Session::connect(
                                log,
                                "ubuntu",
                                SocketAddr::new(
                                    public_ip
                                        .clone()
                                        .parse::<IpAddr>()
                                        .context("machine ip is not an ip address")?,
                                    22,
                                ),
                                Some(private_key_path.path()),
                                None,
                            )
                            .context(format!("failed to ssh to machine {}", &public_dns))
                            .map_err(|e| {
                                error!(log, "failed to ssh to {}", &public_ip);
                                e
                            })?;

                            let (ipinfo, (name, m_setup)) =
                                self.instances.get_mut(&instance_id).unwrap();
                            *ipinfo = Some((public_ip.clone(), public_dns));
                            if let MachineSetup { setup: Some(f), .. } = m_setup {
                                debug!(log, "setting up instance"; "ip" => &public_ip);
                                f(&mut sess, log)
                                    .context(format!(
                                        "setup procedure for {} machine failed",
                                        name
                                    ))
                                    .map_err(|e| {
                                        error!(
                                            log,
                                            "machine setup failed";
                                            "name" => name.clone(),
                                            "ssh" => format!("ssh -i {} ubuntu@{}", private_key_path.path().display(), public_ip),
                                        );
                                        e
                                    })?;
                                info!(log, "finished setting up {} instance", name; "ip" => &public_ip);
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

        Ok(())
    }

    pub fn connect_all<'l>(&'l self) -> Result<HashMap<String, crate::Machine<'l>>, Error> {
        let log = self.log.as_ref().unwrap();
        let private_key_path = self.private_key_path.as_ref().unwrap();
        self.instances
            .values()
            .map(|info| match info {
                (Some((public_ip, public_dns)), (name, MachineSetup { .. })) => {
                    use std::net::{IpAddr, SocketAddr};
                    let sess = ssh::Session::connect(
                        log,
                        "ubuntu",
                        SocketAddr::new(
                            public_ip
                                .parse::<IpAddr>()
                                .context("machine ip is not an ip address")?,
                            22,
                        ),
                        Some(private_key_path.path()),
                        None,
                    )
                    .context(format!("failed to ssh to machine {}", public_dns))
                    .map_err(|e| {
                        error!(log, "failed to ssh to {}", public_ip);
                        e
                    })?;
                    let machine = Machine {
                        public_ip: public_ip.clone(),
                        public_dns: public_dns.clone(),
                        nickname: name.clone(),
                        ssh: Some(sess),
                        _tsunami: Default::default(),
                    };
                    Ok((name.clone(), machine))
                }
                _ => bail!("Machines not initialized"),
            })
            .collect()
    }
}

impl std::ops::Drop for AWSRegion {
    fn drop(&mut self) {
        let client = self.client.as_ref().unwrap();
        let log = self.log.as_ref().expect("AWSRegion uninitialized");
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
        trace!(log, "cleaning up temporary security group");
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

        trace!(log, "cleaning up temporary keypair");
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

#[cfg(test)]
mod test {
    use super::AWSRegion;
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
        let ec2 = AWSRegion::connect(region, provider, test_logger())?;

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
}
