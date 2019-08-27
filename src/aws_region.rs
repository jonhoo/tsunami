use crate::ssh;
use crate::Machine;
use failure::{Error, ResultExt};
use rusoto_core::request::HttpClient;
use rusoto_core::ProvideAwsCredentials;
use rusoto_ec2::Ec2;
use std::collections::HashMap;
use std::io::Write;
use std::{thread, time};

pub struct AWSRegion {
    region: rusoto_core::region::Region,
    security_group_id: String,
    ssh_key_name: String,
    private_key_path: tempfile::NamedTempFile,
    client: rusoto_ec2::Ec2Client,
    outstanding_spot_request_ids: HashMap<String, (String, crate::MachineSetup)>,
    instances: HashMap<String, (String, crate::MachineSetup)>,
    log: slog::Logger,
}

unsafe impl Send for AWSRegion {}

impl AWSRegion {
    pub fn new<P>(
        region: rusoto_core::region::Region,
        provider: P,
        log: slog::Logger,
    ) -> Result<Self, Error>
    where
        P: ProvideAwsCredentials + Send + Sync + 'static,
        <P as ProvideAwsCredentials>::Future: Send,
    {
        let ec2 = AWSRegion::connect(region, provider, log)?
            .make_security_group()?
            .make_ssh_key()?;

        Ok(ec2)
    }

    pub fn region(&self) -> rusoto_core::region::Region {
        self.region.clone()
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
            private_key_path: tempfile::NamedTempFile::new()
                .context("failed to create temporary file for keypair")?,
            outstanding_spot_request_ids: Default::default(),
            instances: Default::default(),
            client: ec2,
            log,
        })
    }

    fn make_security_group(mut self) -> Result<Self, Error> {
        let log = &self.log;
        let ec2 = &mut self.client;
        use rand::Rng;
        let rng = rand::thread_rng();

        // set up network firewall for machines
        let mut group_name = String::from("tsunami_security_");
        group_name.extend(rng.sample_iter(&rand::distributions::Alphanumeric).take(10));
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
        let log = &self.log;
        let ec2 = &mut self.client;
        use rand::Rng;
        let rng = rand::thread_rng();

        // construct keypair for ssh access
        trace!(log, "creating keypair");
        let mut req = rusoto_ec2::CreateKeyPairRequest::default();
        let mut key_name = String::from("tsunami_key_");
        key_name.extend(rng.sample_iter(&rand::distributions::Alphanumeric).take(10));
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

        self.private_key_path
            .write_all(private_key.as_bytes())
            .context("could not write private key to file")?;
        trace!(log, "wrote keypair to file"; "filename" => self.private_key_path.path().display());

        self.ssh_key_name = key_name;
        Ok(self)
    }

    pub fn make_spot_instance_requests(
        &mut self,
        max_duration: i64,
        machines: impl IntoIterator<Item = (String, crate::MachineSetup)>,
    ) -> Result<(), Error> {
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

            trace!(self.log, "issuing spot request");
            let res = self
                .client
                .request_spot_instances(req)
                .sync()
                .context("failed to request spot instance")?;
            let l = self.log.clone();
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
        let start = time::Instant::now();
        let mut req = rusoto_ec2::DescribeSpotInstanceRequestsRequest::default();
        req.spot_instance_request_ids =
            Some(self.outstanding_spot_request_ids.keys().cloned().collect());
        debug!(self.log, "waiting for instances to spawn");

        loop {
            trace!(self.log, "checking spot request status");

            let res = self
                .client
                .describe_spot_instance_requests(req.clone())
                .sync();
            if let Err(e) = res {
                let msg = format!("{}", e);
                if msg.contains("The spot instance request ID") && msg.contains("does not exist") {
                    trace!(self.log, "spot instance requests not yet ready");
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
                        trace!(self.log, "spot request ready"; "state" => state, "id" => &sir.spot_instance_request_id);
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
                            trace!(self.log, "spot request satisfied"; "iid" => &instance_id);

                            Some((instance_id, self.outstanding_spot_request_ids.remove(&sir.spot_instance_request_id.unwrap()).unwrap()))
                        } else {
                            error!(self.log, "spot request failed: {:?}", &sir.status; "state" => &sir.state.unwrap());
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
                    warn!(self.log, "wait time exceeded -- cancelling run");
                    let mut cancel = rusoto_ec2::CancelSpotInstanceRequestsRequest::default();
                    cancel.spot_instance_request_ids = req
                        .spot_instance_request_ids
                        .clone()
                        .expect("we set this to Some above");
                    self.client
                        .cancel_spot_instance_requests(cancel)
                        .sync()
                        .context("failed to cancel spot instances")
                        .map_err(|e| {
                            warn!(self.log, "failed to cancel spot instance request: {:?}", e);
                            e
                        })?;

                    trace!(
                        self.log,
                        "spot instances cancelled -- gathering remaining instances"
                    );
                    // wait for a little while for the cancelled spot requests to settle
                    // and any that were *just* made active to be associated with their instances
                    thread::sleep(time::Duration::from_secs(1));

                    let sirs = self
                        .client
                        .describe_spot_instance_requests(req)
                        .sync()?
                        .spot_instance_requests
                        .unwrap_or_else(Vec::new);
                    for sir in sirs {
                        match sir.instance_id {
                            Some(instance_id) => {
                                trace!(self.log, "spot request cancelled";
                                    "req_id" => sir.spot_instance_request_id,
                                    "iid" => &instance_id,
                                );
                            }
                            _ => {
                                error!(
                                    self.log,
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

    pub fn wait_for_instances(
        &mut self,
        max_wait: Option<time::Duration>,
    ) -> Result<HashMap<String, Machine>, Error> {
        let start = time::Instant::now();
        let mut machines = HashMap::new();
        let mut desc_req = rusoto_ec2::DescribeInstancesRequest::default();
        let mut all_ready = self.instances.is_empty();
        desc_req.instance_ids = Some(self.instances.keys().cloned().collect());
        while !all_ready {
            all_ready = true;
            machines.clear();

            for reservation in self
                .client
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
                            instance_type: Some(instance_type),
                            private_ip_address: Some(private_ip),
                            public_dns_name: Some(public_dns),
                            public_ip_address: Some(public_ip),
                            ..
                        } => {
                            let mut machine = Machine {
                                instance_type,
                                private_ip,
                                public_ip,
                                public_dns,
                                ..Default::default()
                            };
                            trace!(self.log, "instance ready";
                                "instance_id" => instance_id.clone(),
                                "ip" => &machine.public_ip,
                            );
                            use std::net::{IpAddr, SocketAddr};
                            let mut sess = ssh::Session::connect(
                                &self.log,
                                "ubuntu",
                                SocketAddr::new(
                                    machine
                                        .public_ip
                                        .parse::<IpAddr>()
                                        .context("machine ip is not an ip address")?,
                                    22,
                                ),
                                &self.private_key_path.path(),
                                None,
                            )
                            .context(format!("failed to ssh to machine {}", machine.public_dns))
                            .map_err(|e| {
                                error!(self.log, "failed to ssh to {}", &machine.public_ip);
                                e
                            })?;

                            let (name, m_setup) = self.instances.get(&instance_id).unwrap();
                            match m_setup {
                                crate::MachineSetup { setup: Some(f), .. } => {
                                    debug!(self.log, "setting up instance"; "ip" => &machine.public_ip);
                                    f(&mut sess)
                                        .context(format!(
                                            "setup procedure for {} machine failed",
                                            instance_id
                                        ))
                                        .map_err(|e| {
                                            error!(
                                                self.log,
                                                "setup for {} machine failed", instance_id
                                            );
                                            e
                                        })?;
                                    info!(self.log, "finished setting up {} instance", instance_id; "ip" => &machine.public_ip);
                                }
                                _ => {}
                            }

                            machine.ssh = Some(sess);
                            machine.nickname = name.clone();
                            machines.insert(name.clone(), machine);
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

        Ok(machines)
    }
}

impl std::ops::Drop for AWSRegion {
    fn drop(&mut self) {
        // terminate instances
        if !self.instances.is_empty() {
            info!(self.log, "terminating instances");
            let instances = self.instances.keys().cloned().collect();
            self.instances.clear();
            let mut termination_req = rusoto_ec2::TerminateInstancesRequest::default();
            termination_req.instance_ids = instances;
            while let Err(e) = self
                .client
                .terminate_instances(termination_req.clone())
                .sync()
            {
                let msg = format!("{}", e);
                if msg.contains("Pooled stream disconnected") || msg.contains("broken pipe") {
                    trace!(self.log, "retrying instance termination");
                    continue;
                } else {
                    warn!(self.log, "failed to terminate tsunami instances: {:?}", e);
                    break;
                }
            }
        }

        debug!(self.log, "cleaning up temporary resources");
        trace!(self.log, "cleaning up temporary security group");
        // clean up security groups and keys
        let mut req = rusoto_ec2::DeleteSecurityGroupRequest::default();
        req.group_id = Some(self.security_group_id.clone());
        if let Err(e) = self.client.delete_security_group(req).sync() {
            warn!(self.log, "failed to clean up temporary security group";
                "group_id" => &self.security_group_id,
                "error" => ?e,
            )
        }

        trace!(self.log, "cleaning up temporary keypair");
        let mut req = rusoto_ec2::DeleteKeyPairRequest::default();
        req.key_name = self.ssh_key_name.clone();
        if let Err(e) = self.client.delete_key_pair(req).sync() {
            warn!(self.log, "failed to clean up temporary SSH key";
                "key_name" => &self.ssh_key_name,
                "error" => ?e,
            )
        }
    }
}

#[cfg(test)]
mod test {
    use super::AWSRegion;
    use failure::{Error, ResultExt};
    use rusoto_core::region::Region;
    use rusoto_core::DefaultCredentialsProvider;
    use rusoto_ec2::Ec2;

    fn test_logger() -> slog::Logger {
        use slog::Drain;
        let plain = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(plain).build().fuse();
        slog::Logger::root(drain, o!())
    }

    #[test]
    fn make_key() -> Result<(), Error> {
        let region = Region::UsEast1;
        let provider = DefaultCredentialsProvider::new()?;
        let ec2 = AWSRegion::connect(region, provider, test_logger())?;

        let ec2 = ec2.make_ssh_key()?;
        println!("==> key name: {}", ec2.ssh_key_name);
        println!("==> key path: {:?}", ec2.private_key_path);
        assert!(!ec2.ssh_key_name.is_empty());
        assert!(ec2.private_key_path.path().exists());

        let mut req = rusoto_ec2::DeleteKeyPairRequest::default();
        req.key_name = ec2.ssh_key_name.clone();
        ec2.client.delete_key_pair(req).sync().context(format!(
            "Could not delete ssh key pair {:?}",
            ec2.ssh_key_name
        ))?;

        Ok(())
    }
}
