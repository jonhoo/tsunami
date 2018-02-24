//! `tsunami` provides an interface for running short-lived jobs and experiments on EC2 spot block
//! instances. Most interaction with this library happens through
//! [`TsunamiBuilder`](struct.TsunamiBuilder.html).
//!
//! # Examples
//!
//! ```rust,no_run
//! # use tsunami::{Machine, MachineSetup, TsunamiBuilder};
//! # use std::collections::HashMap;
//! let mut b = TsunamiBuilder::default();
//! b.use_term_logger();
//! b.add_set(
//!     "server",
//!     1,
//!     MachineSetup::new("m5.large", "ami-e18aa89b", |ssh| {
//!         ssh.cmd("yum install nginx").map(|out| {
//!             println!("{}", out);
//!         })
//!     }),
//! );
//! b.add_set(
//!     "client",
//!     3,
//!     MachineSetup::new("m5.large", "ami-e18aa89b", |ssh| {
//!         ssh.cmd("yum install wget").map(|out| {
//!             println!("{}", out);
//!         })
//!     }),
//! );
//!
//! b.run(|vms: HashMap<String, Vec<Machine>>| {
//!     println!("==> {}", vms["server"][0].private_ip);
//!     for c in &vms["client"] {
//!         println!(" -> {}", c.private_ip);
//!     }
//!     // ...
//!     Ok(())
//! }).unwrap();
//! ```
//!
//! # Live-coding
//!
//! The crate is under development as part of a live-coding stream series intended for users who
//! are already somewhat familiar with Rust, and who want to see something larger and more involved
//! be built.
//!
//! You can find the recording of the first session at
//! https://youtu.be/Zdudg5TV9i4.
#![deny(missing_docs)]

extern crate failure;
extern crate rand;
extern crate rayon;
extern crate rusoto_core;
extern crate rusoto_ec2;
#[macro_use]
extern crate scopeguard;
#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate ssh2;
extern crate tempfile;

use std::collections::HashMap;
use failure::{Error, ResultExt};
use rayon::prelude::*;
use std::io::Write;
use std::time;

mod ssh;
pub use ssh::Session;

/// A handle to an instance currently running as part of a tsunami.
pub struct Machine {
    /// An established SSH session to this host.
    pub ssh: Option<ssh::Session>,

    /// AWS EC2 instance type hosting this machine.
    ///
    /// See https://aws.amazon.com/ec2/instance-types/ for details.
    pub instance_type: String,

    /// The private IP address of this host on its designated VPC.
    pub private_ip: String,

    /// The publicly accessible hostname of this host.
    pub public_dns: String,

    /// The publicly accessible IP address of this host.
    pub public_ip: String,
}

/// A template for a particular machine setup in a tsunami.
pub struct MachineSetup {
    instance_type: String,
    ami: String,
    setup: Box<Fn(&mut ssh::Session) -> Result<(), Error> + Sync>,
}

impl MachineSetup {
    /// Define a new template for a tsunami machine setup.
    ///
    /// The given AWS EC2 instance type will be used. Note that only [EC2 Defined Duration Spot
    /// Instance types](https://aws.amazon.com/ec2/spot/pricing/) are allowed.
    ///
    /// The `setup` argument is called once for every spawned instances of this type with a handle
    /// to the target machine. Use [`Machine::ssh`](struct.Machine.html#structfield.ssh) to issue
    /// commands on the host in question.
    ///
    /// The new instance will start out in the state dictated by the Amazon Machine Image specified
    /// in `ami`.
    ///
    /// ```rust
    /// # use tsunami::MachineSetup;
    /// MachineSetup::new("m5.large", "ami-e18aa89b", |ssh| {
    ///     ssh.cmd("cat /etc/hostname").map(|out| {
    ///         println!("{}", out);
    ///     })
    /// });
    /// ```
    pub fn new<F>(instance_type: &str, ami: &str, setup: F) -> Self
    where
        F: Fn(&mut ssh::Session) -> Result<(), Error> + 'static + Sync,
    {
        MachineSetup {
            instance_type: instance_type.to_string(),
            ami: ami.to_string(),
            setup: Box::new(setup),
        }
    }
}

/// Use this to prepare and execute a new tsunami.
///
/// A tsunami consists of one or more [`MachineSetup`](struct.MachineSetup.html)s that will be
/// spawned as EC2 spot instances. See
/// [`MachineSetup#add_set`](struct.TsunamiBuilder.html#method.add_set)) for how to construct a
/// tsunami.
#[must_use]
pub struct TsunamiBuilder {
    descriptors: HashMap<String, (MachineSetup, u32)>,
    log: slog::Logger,
    max_duration: i64,
}

impl Default for TsunamiBuilder {
    fn default() -> Self {
        TsunamiBuilder {
            descriptors: Default::default(),
            log: slog::Logger::root(slog::Discard, o!()),
            max_duration: 60,
        }
    }
}

impl TsunamiBuilder {
    /// Add a new (named) machine setup template, and set how many instances of that type should be
    /// spawned as part of the tsunami.
    ///
    /// ```rust
    /// # use tsunami::{TsunamiBuilder, MachineSetup};
    /// let mut b = TsunamiBuilder::default();
    /// b.add_set(
    ///     "server",
    ///     1,
    ///     MachineSetup::new("m5.large", "ami-e18aa89b", |ssh| {
    ///         ssh.cmd("yum install nginx").map(|out| {
    ///             println!("{}", out);
    ///         })
    ///     }),
    /// );
    /// b.add_set(
    ///     "client",
    ///     10,
    ///     MachineSetup::new("m5.large", "ami-e18aa89b", |ssh| {
    ///         ssh.cmd("yum install wget").map(|out| {
    ///             println!("{}", out);
    ///         })
    ///     }),
    /// );
    /// ```
    pub fn add_set(&mut self, name: &str, number: u32, setup: MachineSetup) {
        // TODO: what if name is already in use?
        self.descriptors.insert(name.to_string(), (setup, number));
    }

    /// Set the maxium lifetime of spawned spot instances.
    ///
    /// EC2 spot instances are normally subject to termination at any point. This library instead
    /// uses [defined
    /// duration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-requests.html#fixed-duration-spot-instances)
    /// instances, which cost slightly more, but are never prematurely terminated. The lifetime of
    /// such instances must be declared in advance (1-6 hours), and can be changed with this
    /// method.
    ///
    /// The default duration is 1 hour.
    pub fn set_max_duration(&mut self, hours: u8) {
        self.max_duration = hours as i64 * 60;
    }

    /// Set the logging target for this tsunami.
    ///
    /// By default, logging is disabled (i.e., the default logger is `slog::Discard`).
    pub fn set_logger(&mut self, log: slog::Logger) {
        self.log = log;
    }

    /// Enable logging to terminal.
    pub fn use_term_logger(&mut self) {
        use slog::Drain;
        use std::sync::Mutex;

        let decorator = slog_term::TermDecorator::new().build();
        let drain = Mutex::new(slog_term::FullFormat::new(decorator).build()).fuse();
        self.log = slog::Logger::root(drain, o!());
    }

    /// Spin up a tsunami batching the defined machine sets in this builder.
    ///
    /// When all instances are up and running, the given closure will be called with a handle to
    /// all spawned hosts. When the closure exits, the instances are all terminated automatically.
    ///
    /// ```rust,no_run
    /// # use tsunami::{TsunamiBuilder, Machine};
    /// # use std::collections::HashMap;
    /// let mut b = TsunamiBuilder::default();
    /// // ...
    /// b.run(|vms: HashMap<String, Vec<Machine>>| {
    ///     println!("==> {}", vms["server"][0].private_ip);
    ///     for c in &vms["client"] {
    ///         println!(" -> {}", c.private_ip);
    ///     }
    ///     Ok(())
    /// }).unwrap();
    pub fn run<F>(self, f: F) -> Result<(), Error>
    where
        F: FnOnce(HashMap<String, Vec<Machine>>) -> Result<(), Error>,
    {
        use rusoto_core::{EnvironmentProvider, Region};
        use rusoto_core::default_tls_client;
        use rusoto_ec2::Ec2;

        let log = &self.log;

        debug!(log, "connecting to ec2");

        let ec2 = rusoto_ec2::Ec2Client::new(
            default_tls_client().context("failed to create tls session for ec2 api client")?,
            EnvironmentProvider,
            Region::UsEast1,
        );

        info!(log, "spinning up tsunami");

        // set up network firewall for machines
        use rand::Rng;
        let mut group_name = String::from("tsunami_security_");
        group_name.extend(rand::thread_rng().gen_ascii_chars().take(10));
        trace!(log, "creating security group"; "name" => &group_name);
        let mut req = rusoto_ec2::CreateSecurityGroupRequest::default();
        req.group_name = group_name;
        req.description = "temporary access group for tsunami VMs".to_string();
        let res = ec2.create_security_group(&req)
            .context("failed to create security group for new machines")?;
        let group_id = res.group_id
            .expect("aws created security group with no group id");
        trace!(log, "created security group"; "id" => &group_id);

        let mut req = rusoto_ec2::AuthorizeSecurityGroupIngressRequest::default();
        req.group_id = Some(group_id.clone());

        // ssh access
        req.ip_protocol = Some("tcp".to_string());
        req.from_port = Some(22);
        req.to_port = Some(22);
        req.cidr_ip = Some("0.0.0.0/0".to_string());
        trace!(log, "adding ssh access to security group");
        let _ = ec2.authorize_security_group_ingress(&req)
            .context("failed to fill in security group for new machines")?;

        // cross-VM talk
        req.from_port = Some(0);
        req.to_port = Some(65535);
        req.cidr_ip = Some("172.31.0.0/16".to_string());
        trace!(log, "adding internal VM access to security group");
        let _ = ec2.authorize_security_group_ingress(&req)
            .context("failed to fill in security group for new machines")?;

        // construct keypair for ssh access
        trace!(log, "creating keypair");
        let mut req = rusoto_ec2::CreateKeyPairRequest::default();
        let mut key_name = String::from("tsunami_key_");
        key_name.extend(rand::thread_rng().gen_ascii_chars().take(10));
        req.key_name = key_name.clone();
        let res = ec2.create_key_pair(&req)
            .context("failed to generate new key pair")?;
        trace!(log, "created keypair"; "fingerprint" => res.key_fingerprint);

        // write keypair to disk
        let private_key = res.key_material
            .expect("aws did not generate key material for new key");
        let mut private_key_file =
            tempfile::NamedTempFile::new().context("failed to create temporary file for keypair")?;
        private_key_file
            .write_all(private_key.as_bytes())
            .context("could not write private key to file")?;
        trace!(log, "wrote keypair to file"; "filename" => ?private_key_file.path());

        let mut setup_fns = HashMap::new();

        // 1. issue spot requests
        let mut id_to_name = HashMap::new();
        let mut spot_req_ids = Vec::new();
        debug!(log, "issuing spot requests");
        // TODO: issue spot requests in parallel
        for (name, (setup, number)) in self.descriptors {
            let mut launch = rusoto_ec2::RequestSpotLaunchSpecification::default();
            launch.image_id = Some(setup.ami);
            launch.instance_type = Some(setup.instance_type);
            setup_fns.insert(name.clone(), setup.setup);

            launch.security_group_ids = Some(vec![group_id.clone()]);
            launch.key_name = Some(key_name.clone());

            // TODO: VPC

            let mut req = rusoto_ec2::RequestSpotInstancesRequest::default();
            req.instance_count = Some(i64::from(number));
            req.block_duration_minutes = Some(self.max_duration);
            req.launch_specification = Some(launch);

            trace!(log, "issuing spot request for {}", name; "#" => number);
            let res = ec2.request_spot_instances(&req)
                .context(format!("failed to request spot instances for {}", name))?;
            let res = res.spot_instance_requests
                .expect("request_spot_instances should always return spot instance requests");
            spot_req_ids.extend(
                res.into_iter()
                    .filter_map(|sir| sir.spot_instance_request_id)
                    .map(|sir| {
                        // TODO: add more info if in parallel
                        trace!(log, "activated spot request"; "id" => &sir);
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
        debug!(log, "waiting for instances to spawn");
        loop {
            trace!(log, "checking spot request status");

            let res = ec2.describe_spot_instance_requests(&req);
            if let Err(e) = res {
                let msg = format!("{}", e);
                if msg.contains("The spot instance request ID") && msg.contains("does not exist") {
                    trace!(log, "spot instance requests not yet ready");
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
                    if state == "open" || (state == "active" && sir.instance_id.is_none()) {
                        true
                    } else {
                        trace!(log, "spot request is not yet ready"; "state" => state, "id" => &sir.spot_instance_request_id);
                        false
                    }
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
                            trace!(log, "spot request satisfied"; "set" => &name, "iid" => &instance_id);
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

        let mut term_instances = instances.clone();
        defer!{{
            use std::mem;

            // 6. terminate all instances
            debug!(log, "terminating instances");
            let mut termination_req = rusoto_ec2::TerminateInstancesRequest::default();
            termination_req.instance_ids = mem::replace(&mut term_instances, Vec::new());
            while let Err(e) = ec2.terminate_instances(&termination_req) {
                let msg = format!("{}", e);
                if msg.contains("Pooled stream disconnected") || msg.contains("broken pipe") {
                    trace!(log, "retrying instance termination");
                    continue;
                } else {
                    warn!(log, "failed to terminate tsunami instances: {:?}", e);
                }
            }

            /*
            debug!(log, "cleaning up temporary resources");
            trace!(log, "cleaning up temporary security group");
            // clean up security groups and keys
            let mut req = rusoto_ec2::DeleteSecurityGroupRequest::default();
            req.group_id = Some(group_id);
            ec2.delete_security_group(&req)
                .context("failed to clean up security group")?;
            trace!(log, "cleaning up temporary keypair");
            let mut req = rusoto_ec2::DeleteKeyPairRequest::default();
            req.key_name = key_name;
            ec2.delete_key_pair(&req)
            .context("failed to clean up key pair")?;
            */
        }};

        // 3. stop spot requests
        trace!(log, "terminating spot requests");
        let mut cancel = rusoto_ec2::CancelSpotInstanceRequestsRequest::default();
        cancel.spot_instance_request_ids = req.spot_instance_request_ids
            .take()
            .expect("we set this to Some above");
        ec2.cancel_spot_instance_requests(&cancel)
            .context("failed to cancel spot instances")
            .map_err(|e| {
                warn!(log, "failed to cancel spot instance request: {:?}", e);
                e
            })?;

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
                            trace!(log, "instance ready"; "set" => &name, "ip" => &machine.public_ip);
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

        let mut errors = Vec::new();
        if all_active {
            info!(log, "all machines instantiated; running setup");

            //    - once an instance is ready, run setup closure
            for (name, machines) in &mut machines {
                let f = &setup_fns[name];
                errors.par_extend(
                    machines
                        .par_iter_mut()
                        .map(|machine| -> Result<_, Error> {
                            use std::net::{IpAddr, SocketAddr};
                            let mut sess = ssh::Session::connect(
                                SocketAddr::new(
                                    machine
                                        .public_ip
                                        .parse::<IpAddr>()
                                        .context("machine ip is not an ip address")?,
                                    22,
                                ),
                                private_key_file.path(),
                            ).context(format!(
                                "failed to ssh to {} machine {}",
                                name, machine.public_dns
                            ))
                                .map_err(|e| {
                                    error!(
                                        log,
                                        "failed to ssh to {}:{}", &name, &machine.public_ip
                                    );
                                    e
                                })?;

                            debug!(log, "setting up {} instance", name; "ip" => &machine.public_ip);
                            f(&mut sess)
                                .context(format!("setup procedure for {} machine failed", name))
                                .map_err(|e| {
                                    error!(log, "setup for {} machine failed", name);
                                    e
                                })?;
                            info!(log, "finished setting up {} instance", name; "ip" => &machine.public_ip);

                            machine.ssh = Some(sess);
                            Ok(())
                        })
                        .filter_map(Result::err),
                );
            }

            if errors.is_empty() {
                // 5. invoke F with Machine descriptors
                let start = time::Instant::now();
                info!(log, "quiet before the storm");
                f(machines)
                    .context("tsunami main routine failed")
                    .map_err(|e| {
                        crit!(log, "main tsunami routine failed");
                        e
                    })?;
                info!(log, "the power of the tsunami was unleashed"; "duration" => start.elapsed().as_secs());
            }
        }

        debug!(log, "all done");

        // TODO: this will only expose first setup error -- fix that
        errors.into_iter().next().map(|e| Err(e)).unwrap_or(Ok(()))
    }
}
