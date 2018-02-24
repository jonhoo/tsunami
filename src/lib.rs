extern crate failure;
extern crate rusoto_core;
extern crate rusoto_ec2;
extern crate ssh2;

use std::collections::HashMap;
use failure::{Error, ResultExt};

mod ssh;

//#[derive(Debug, Fail)]
//pub enum TsunamiError { }

pub struct Machine {
    pub ssh: Option<ssh::Session>,
    pub instance_type: String,
    pub private_ip: String,
    pub public_dns: String,
    pub public_ip: String,
}

pub struct MachineSetup {
    instance_type: String,
    ami: String,
    setup: Box<Fn(&mut ssh::Session) -> Result<(), Error>>,
}

impl MachineSetup {
    pub fn new<F>(instance_type: &str, ami: &str, setup: F) -> Self
    where
        F: Fn(&mut ssh::Session) -> Result<(), Error> + 'static,
    {
        MachineSetup {
            instance_type: instance_type.to_string(),
            ami: ami.to_string(),
            setup: Box::new(setup),
        }
    }
}

pub struct TsunamiBuilder {
    descriptors: HashMap<String, (MachineSetup, u32)>,
    max_duration: i64,
}

impl Default for TsunamiBuilder {
    fn default() -> Self {
        TsunamiBuilder {
            descriptors: Default::default(),
            max_duration: 60,
        }
    }
}

impl TsunamiBuilder {
    pub fn add_set(&mut self, name: &str, number: u32, setup: MachineSetup) {
        // TODO: what if name is already in use?
        self.descriptors.insert(name.to_string(), (setup, number));
    }

    pub fn set_max_duration(&mut self, hours: u8) {
        self.max_duration = hours as i64 * 60;
    }

    pub fn run<F>(self, f: F) -> Result<(), Error>
    where
        F: FnOnce(HashMap<String, Vec<Machine>>) -> Result<(), Error>,
    {
        use rusoto_core::{EnvironmentProvider, Region};
        use rusoto_core::default_tls_client;
        use rusoto_ec2::Ec2;

        let ec2 = rusoto_ec2::Ec2Client::new(
            default_tls_client().context("failed to create tls session for ec2 api client")?,
            EnvironmentProvider,
            Region::UsEast1,
        );

        let mut setup_fns = HashMap::new();

        // 1. issue spot requests
        let mut id_to_name = HashMap::new();
        let mut spot_req_ids = Vec::new();
        for (name, (setup, number)) in self.descriptors {
            let mut launch = rusoto_ec2::RequestSpotLaunchSpecification::default();
            launch.image_id = Some(setup.ami);
            launch.instance_type = Some(setup.instance_type);
            setup_fns.insert(name.clone(), setup.setup);

            // TODO
            launch.security_groups = Some(vec!["hello".to_string()]);
            launch.key_name = Some("x1c".to_string());
            // TODO: VPC

            let mut req = rusoto_ec2::RequestSpotInstancesRequest::default();
            req.instance_count = Some(i64::from(number));
            req.block_duration_minutes = Some(self.max_duration);
            req.launch_specification = Some(launch);

            let res = ec2.request_spot_instances(&req)
                .context(format!("failed to request spot instances for {}", name))?;
            let res = res.spot_instance_requests
                .expect("request_spot_instances should always return spot instance requests");
            spot_req_ids.extend(
                res.into_iter()
                    .filter_map(|sir| sir.spot_instance_request_id)
                    .map(|sir| {
                        id_to_name.insert(sir.clone(), name.clone());
                        sir
                    }),
            );
        }

        // 2. wait for instances to come up
        let mut req = rusoto_ec2::DescribeSpotInstanceRequestsRequest::default();
        req.spot_instance_request_ids = Some(spot_req_ids);

        let mut all_active;
        let instances: Vec<_>;
        loop {
            let res = ec2.describe_spot_instance_requests(&req);
            if let Err(e) = res {
                let msg = format!("{}", e);
                if msg.contains("The spot instance request ID") && msg.contains("does not exist") {
                    continue;
                } else {
                    return Err(e)
                        .context(format!("failed to describe spot instances"))
                        .map_err(|e| e.into());
                }
            }
            let res = res.expect("Err checked above");

            let any_pending = res.spot_instance_requests
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
                    state == "open" || (state == "active" && sir.instance_id.is_none())
                });

            if !any_pending {
                all_active = true;
                // unwraps okay because they are the same as expects above
                instances = res.spot_instance_requests
                    .unwrap()
                    .into_iter()
                    .filter_map(|sir| {
                        if sir.state.unwrap() == "active" {
                            let name = id_to_name
                                .remove(&sir.spot_instance_request_id
                                    .expect("spot request must have spot request id"))
                                .expect("every spot request id is made for some machine set");

                            // unwrap ok because active implies instance_id.is_some()
                            // because !any_pending
                            let instance_id = sir.instance_id.unwrap();
                            id_to_name.insert(instance_id.clone(), name);

                            Some(instance_id)
                        } else {
                            all_active = false;
                            None
                        }
                    })
                    .collect();
                break;
            } else {
                use std::{thread, time};
                thread::sleep(time::Duration::from_millis(500));
            }
        }

        // TODO: this is where we'd create the ScopeGuard

        // 3. stop spot requests
        let mut cancel = rusoto_ec2::CancelSpotInstanceRequestsRequest::default();
        cancel.spot_instance_request_ids = req.spot_instance_request_ids
            .take()
            .expect("we set this to Some above");
        ec2.cancel_spot_instance_requests(&cancel)
            .context("failed to cancel spot instances")?;

        // 4. wait until all instances are up
        let mut machines = HashMap::new();
        let mut desc_req = rusoto_ec2::DescribeInstancesRequest::default();
        desc_req.instance_ids = Some(instances);
        let mut all_ready = false;
        while !all_ready {
            all_ready = true;
            machines.clear();

            for reservation in ec2.describe_instances(&desc_req)
                .context("failed to cancel spot instances")?
                .reservations
                .unwrap_or_else(Vec::new)
            {
                for instance in reservation.instances.unwrap_or_else(Vec::new) {
                    match instance {
                        rusoto_ec2::Instance {
                            instance_id: Some(instance_id),
                            instance_type: Some(instance_type),
                            private_ip_address: Some(private_ip),
                            public_dns_name: Some(public_dns),
                            public_ip_address: Some(public_ip),
                            ..
                        } => {
                            let machine = Machine {
                                ssh: None,
                                instance_type,
                                private_ip,
                                public_ip,
                                public_dns,
                            };
                            let name = id_to_name[&instance_id].clone();
                            machines.entry(name).or_insert_with(Vec::new).push(machine);
                        }
                        _ => {
                            all_ready = false;
                        }
                    }
                }
            }
        }

        // TODO: assert here that #instances in each set is the same as requested

        if all_active {
            //    - once an instance is ready, run setup closure
            for (name, machines) in &mut machines {
                let f = &setup_fns[name];
                // TODO: set up machines in parallel (rayon)
                for machine in machines {
                    let mut sess = ssh::Session::connect(&format!("{}:22", machine.public_ip))
                        .context(format!(
                            "failed to ssh to {} machine {}",
                            name, machine.public_dns
                        })?;

                    f(&mut sess).map_err(|e| {
                        e.context(format!("setup procedure for {} machine failed", name))
                    })?;

                    machine.ssh = Some(sess);
                }
            }

            // 5. invoke F with Machine descriptors
            f(machines).map_err(|e| e.context("tsunami main routine failed"))?;
        }

        // 6. terminate all instances
        let mut termination_req = rusoto_ec2::TerminateInstancesRequest::default();
        termination_req.instance_ids = desc_req.instance_ids.expect("set to Some further up");
        while let Err(e) = ec2.terminate_instances(&termination_req) {
            let msg = format!("{}", e);
            if msg.contains("Pooled stream disconnected") || msg.contains("broken pipe") {
                continue;
            } else {
                Err(e).context("failed to terminate tsunami instances")?;
            }
        }

        Ok(())
    }
}
