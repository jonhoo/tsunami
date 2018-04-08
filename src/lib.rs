//! `tsunami` provides an interface for running short-lived jobs and experiments on EC2 spot block
//! instances. Most interaction with this library happens through
//! [`TsunamiBuilder`](struct.TsunamiBuilder.html).
//!
//! # Examples
//!
//! ```rust,no_run
//! # extern crate tokio_core;
//! # extern crate tsunami;
//! # extern crate futures;
//! # fn main() {
//! # use tsunami::{Machine, MachineSetup, TsunamiBuilder};
//! # use std::collections::HashMap;
//! let mut b = TsunamiBuilder::default();
//! b.use_term_logger();
//!
//! use futures::Future;
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
//! let mut core = tokio_core::reactor::Core::new().unwrap();
//! let handle = core.handle();
//! let fut = b.run(&handle, |vms: HashMap<&str, Vec<Machine>>| {
//!     println!("==> {}", vms["server"][0].private_ip);
//!     for c in &vms["client"] {
//!         println!(" -> {}", c.private_ip);
//!     }
//!     // ...
//!     Ok(())
//! });
//! core.run(fut).unwrap();
//! # }
//! ```
//!
//! # Live-coding
//!
//! The crate is under development as part of a live-coding stream series intended for users who
//! are already somewhat familiar with Rust, and who want to see something larger and more involved
//! be built.
//!
//! You can find the recordings of past sessions below:
//! - [Part 1](https://youtu.be/Zdudg5TV9i4)
//! - [Part 2](https://youtu.be/66INYb73yXo)
#![deny(missing_docs)]

#[macro_use]
extern crate failure;
extern crate rand;
extern crate rusoto_core;
extern crate rusoto_ec2;
#[macro_use]
extern crate slog;
extern crate async_ssh;
extern crate futures;
extern crate slog_term;
extern crate thrussh_keys;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_timer;

use failure::{Error, ResultExt};
use futures::future::{self, Either};
use futures::{Future, IntoFuture};
use rand::Rng;
use rusoto_core::Region;
use std::collections::HashMap;
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
    username: String,
    setup: Box<Fn(&mut ssh::Session) -> Box<Future<Item = (), Error = Error>>>,
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
    /// # extern crate futures;
    /// # extern crate tsunami;
    /// # fn main() {
    /// # use tsunami::MachineSetup;
    /// use futures::Future;
    /// MachineSetup::new("m5.large", "ami-e18aa89b", |ssh| {
    ///     ssh.cmd("cat /etc/hostname").map(|out| {
    ///         println!("{}", out);
    ///     })
    /// });
    /// # }
    /// ```
    pub fn new<F, FF>(instance_type: &str, ami: &str, setup: F) -> Self
    where
        F: Fn(&mut ssh::Session) -> FF + 'static,
        FF: IntoFuture<Item = (), Error = Error> + 'static,
    {
        MachineSetup {
            instance_type: instance_type.to_string(),
            ami: ami.to_string(),
            username: String::from("ec2-user"),
            setup: Box::new(move |ssh| Box::new(setup(ssh).into_future())),
        }
    }

    /// Set the username to SSH into this machine type as.
    ///
    /// Defaults to `ec2-user`.
    pub fn as_user(mut self, username: &str) -> Self {
        self.username = username.to_string();
        self
    }
}

#[derive(Default, Clone)]
struct SpotRequestResult<'a> {
    id_to_name: HashMap<String, &'a str>,
    setup_fns:
        HashMap<&'a str, &'a Box<Fn(&mut ssh::Session) -> Box<Future<Item = (), Error = Error>>>>,
    usernames: HashMap<&'a str, &'a str>,
    spot_req_ids: Vec<String>,
}

#[derive(Debug, Fail)]
enum TsunamiError {
    #[fail(display = "failed to create security group for new machines: {:?}", error)]
    SecurityGroupCreate {
        error: rusoto_ec2::CreateSecurityGroupError,
    },

    #[fail(display = "failed to fill in security group for new machines: {:?}", error)]
    SecurityGroupConfigure {
        error: rusoto_ec2::AuthorizeSecurityGroupIngressError,
    },

    #[fail(display = "failed to generate new key pair: {:?}", error)]
    KeyPair {
        error: rusoto_ec2::CreateKeyPairError,
    },

    #[fail(display = "failed to create new placement group: {:?}", error)]
    PlacementGroups {
        error: rusoto_ec2::CreatePlacementGroupError,
    },

    #[fail(display = "failed to request spot instances for {}: {:?}", name, error)]
    RequestSpotInstances {
        name: String,
        error: rusoto_ec2::RequestSpotInstancesError,
    },

    #[fail(display = "failed to describe spot instances")]
    Describe,

    #[fail(display = "timer error: {}", error)]
    Timer { error: tokio_timer::Error },

    #[fail(display = "failed to cancel spot instances: {:?}", error)]
    Cancel {
        error: rusoto_ec2::CancelSpotInstanceRequestsError,
    },

    #[fail(display = "failed to find instances after cancellation: {:?}", error)]
    FindAfterCancellation {
        error: rusoto_ec2::DescribeSpotInstanceRequestsError,
    },

    #[fail(display = "not all instances were launched within the time limit")]
    Timeout { instances: Vec<String> },

    #[fail(display = "failed to describe spot instances after launch: {:?}", error)]
    DescribeWithInstances {
        error: rusoto_ec2::DescribeInstancesError,
        instances: Vec<String>,
    },

    #[fail(display = "tsunami main routine failed")]
    MainRoutine {
        error: Box<Error>,
        instances: Vec<String>,
    },
}

impl TsunamiError {
    fn get_term_instances(&self) -> Option<Vec<String>> {
        match self {
            | TsunamiError::Timeout { ref instances }
            | TsunamiError::DescribeWithInstances { ref instances, .. }
            | TsunamiError::MainRoutine { ref instances, .. } => Some(instances.clone()),
            _ => None,
        }
    }
}

/// Use this to prepare and execute a new tsunami.
///
/// A tsunami consists of one or more [`MachineSetup`](struct.MachineSetup.html)s that will be
/// spawned as EC2 spot instances. See
/// [`TsunamiBuilder#add_set`](struct.TsunamiBuilder.html#method.add_set)) for how to construct a
/// tsunami.
#[must_use]
pub struct TsunamiBuilder {
    descriptors: HashMap<String, (MachineSetup, u32)>,
    log: slog::Logger,
    max_duration: i64,
    region: Region,
    cluster: bool,
    max_wait: Option<time::Duration>,
    ec2: Option<Box<rusoto_ec2::Ec2>>,
}

impl Default for TsunamiBuilder {
    fn default() -> Self {
        TsunamiBuilder {
            descriptors: Default::default(),
            log: slog::Logger::root(slog::Discard, o!()),
            max_duration: 60,
            region: Region::UsEast1,
            cluster: true,
            max_wait: None,
            ec2: None,
        }
    }
}

impl TsunamiBuilder {
    /// Add a new (named) machine setup template, and set how many instances of that type should be
    /// spawned as part of the tsunami.
    ///
    /// ```rust
    /// # extern crate futures;
    /// # extern crate tsunami;
    /// # fn main() {
    /// # use tsunami::{TsunamiBuilder, MachineSetup};
    /// use futures::Future;
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
    /// # }
    /// ```
    pub fn add_set(&mut self, name: &str, number: u32, setup: MachineSetup) {
        // TODO: what if name is already in use?
        self.descriptors.insert(name.to_string(), (setup, number));
    }

    /// Set up the machines in a specific EC2
    /// [`Region`](http://rusoto.github.io/rusoto/rusoto_core/region/enum.Region.html).
    ///
    /// The default region is us-east-1. [Available regions are listed
    /// here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions)
    pub fn set_region(&mut self, region: Region) {
        self.region = region;
    }

    /// By default, all spawned instances are launched in a single [Placement
    /// Group](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/placement-groups.html) using the
    /// [cluster](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/placement-groups.html#placement-groups-cluster)
    /// policy. This ensures that all the instances are located in the same availability region,
    /// and in close proximity to one another.
    ///
    /// This places [some
    /// restrictions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/placement-groups.html#concepts-placement-groups)
    /// on the launched instances, and causes it to be more likely for placements to fail. Call
    /// this method to disable clustering. This will leave instance placing entirely up to ec2,
    /// which may choose to place your instances in disparate availability zones.
    pub fn no_clustering(&mut self) {
        self.cluster = false;
    }

    /// Limit how long we should wait for spot requests to be satisfied before giving up.
    pub fn wait_limit(&mut self, t: time::Duration) {
        self.max_wait = Some(t);
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
    /// This method uses the rusoto
    /// [`EnvironmentProvider`](https://docs.rs/rusoto_credential/0.10.0/rusoto_credential/struct.EnvironmentProvider.html),
    /// which uses standard [AWS environtment
    /// variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-environment.html) for
    /// authentication.
    ///
    /// ```rust,no_run
    /// # extern crate tokio_core;
    /// # extern crate tsunami;
    /// # fn main() {
    /// # use tsunami::{TsunamiBuilder, Machine};
    /// # use std::collections::HashMap;
    /// let mut b = TsunamiBuilder::default();
    /// // ...
    /// let mut core = tokio_core::reactor::Core::new().unwrap();
    /// let handle = &core.handle();
    /// let fut = b.run(&handle, |vms: HashMap<&str, Vec<Machine>>| {
    ///     println!("==> {}", vms["server"][0].private_ip);
    ///     for c in &vms["client"] {
    ///         println!(" -> {}", c.private_ip);
    ///     }
    ///     Ok(())
    /// });
    /// core.run(fut).unwrap();
    /// # }
    pub fn run<'a, F, FF>(
        &'a mut self,
        handle: &'a tokio_core::reactor::Handle,
        f: F,
    ) -> Box<Future<Item = (), Error = Error> + 'a>
    where
        F: 'a + FnOnce(HashMap<&'a str, Vec<Machine>>) -> FF,
        FF: 'a + IntoFuture<Item = (), Error = Error>,
    {
        self.run_as(rusoto_core::EnvironmentProvider, handle, f)
    }

    /// Spin up a tsunami batching the defined machine sets in this builder with a custom
    /// credentials provider.
    ///
    /// When all instances are up and running, the given closure will be called with a handle to
    /// all spawned hosts. When the closure exits, the instances are all terminated automatically.
    ///
    /// ```rust,no_run
    /// # extern crate rusoto_core;
    /// # extern crate rusoto_sts;
    /// # extern crate tsunami;
    /// # extern crate tokio_core;
    /// # fn main() {
    /// # use tsunami::{TsunamiBuilder, Machine};
    /// # use std::collections::HashMap;
    /// // https://github.com/rusoto/rusoto/blob/master/AWS-CREDENTIALS.md
    /// let sts = rusoto_sts::StsClient::new(
    ///     rusoto_core::reactor::RequestDispatcher::default(),
    ///     rusoto_core::EnvironmentProvider,
    ///     rusoto_core::region::Region::UsEast1,
    /// );
    /// let provider = rusoto_sts::StsAssumeRoleSessionCredentialsProvider::new(
    ///     sts,
    ///     "arn:aws:sts::1122334455:role/myrole".to_owned(),
    ///     "session-name".to_owned(),
    ///     None,
    ///     None,
    ///     None,
    ///     None,
    /// );
    ///
    /// let mut b = TsunamiBuilder::default();
    /// // ...
    /// let mut core = tokio_core::reactor::Core::new().unwrap();
    /// let handle = &core.handle();
    /// let fut = b.run_as(provider, &handle, |vms: HashMap<&str, Vec<Machine>>| {
    ///     println!("==> {}", vms["server"][0].private_ip);
    ///     for c in &vms["client"] {
    ///         println!(" -> {}", c.private_ip);
    ///     }
    ///     Ok(())
    /// });
    /// core.run(fut).unwrap();
    /// # }
    pub fn run_as<'a, P, F, FF>(
        &'a mut self,
        provider: P,
        handle: &'a tokio_core::reactor::Handle,
        f: F,
    ) -> Box<Future<Item = (), Error = Error> + 'a>
    where
        P: 'static + rusoto_core::ProvideAwsCredentials,
        F: 'a + FnOnce(HashMap<&'a str, Vec<Machine>>) -> FF,
        FF: 'a + IntoFuture<Item = (), Error = Error>,
    {
        use rusoto_core::reactor::RequestDispatcher;

        debug!(self.log, "connecting to ec2");
        self.ec2 = Some(Box::new(rusoto_ec2::Ec2Client::new(
            RequestDispatcher::default(),
            provider,
            self.region.clone(),
        )));

        let this = &*self; // so we can have all the futures share self
        let ec2 = this.ec2.as_ref().unwrap();
        let log = &this.log;
        let expected_num: u32 = this.descriptors.values().map(|&(_, n)| n).sum();

        let all_the_things = future::lazy(move || Self::configure_sg(log, ec2))
            .and_then(move |group_id| {
                // construct keypair for ssh access
                Self::configure_ssh(log, ec2).map(|(pk, key_name)| (pk, key_name, group_id))
            })
            .and_then(move |(pk, key_name, group_id)| {
                if this.cluster {
                    Either::A(Self::configure_placement_groups(log, ec2))
                } else {
                    Either::B(future::ok(None))
                }.map(move |placement| (placement, pk, group_id, key_name))
            })
            .and_then(move |(placement, pk, group_id, key_name)| {
                Self::issue_spot_requests(
                    log,
                    ec2,
                    &this.descriptors,
                    this.max_duration,
                    placement,
                    key_name,
                    group_id,
                ).map(|req| (req, pk))
            })
            .and_then(
                move |(
                    SpotRequestResult {
                        id_to_name,
                        setup_fns,
                        usernames,
                        spot_req_ids,
                    },
                    pk,
                )| {
                    Self::wait_for_instances(log, ec2, spot_req_ids, id_to_name, this.max_wait).map(
                        |(machines, instances)| (machines, instances, setup_fns, usernames, pk),
                    )
                },
            )
            .and_then(move |(machines, instances, setup_fns, usernames, pk)| {
                Self::setup_and_run(
                    log,
                    machines,
                    setup_fns,
                    usernames,
                    pk,
                    expected_num,
                    handle,
                    f,
                ).then(|r| match r {
                    Ok(_) => Ok(instances),
                    Err(error) => Err(TsunamiError::MainRoutine {
                        error: Box::new(error),
                        instances,
                    }),
                })
            })
            .then(move |r| Self::clean_up(log, ec2, r));
        Box::new(all_the_things)
    }

    fn configure_sg<'a>(
        log: &'a slog::Logger,
        ec2: &'a Box<rusoto_ec2::Ec2>,
    ) -> Box<Future<Item = String, Error = TsunamiError> + 'a> {
        info!(log, "spinning up tsunami");

        // set up network firewall for machines
        let mut group_name = String::from("tsunami_security_");
        group_name.extend(rand::thread_rng().gen_ascii_chars().take(10));
        trace!(log, "creating security group"; "name" => &group_name);
        let mut req = rusoto_ec2::CreateSecurityGroupRequest::default();
        req.group_name = group_name;
        req.description = "temporary access group for tsunami VMs".to_string();
        let future = ec2.create_security_group(&req)
            .map_err(|error| TsunamiError::SecurityGroupCreate { error })
            .and_then(move |res| {
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
                ec2.authorize_security_group_ingress(&req)
                    .map_err(|error| TsunamiError::SecurityGroupConfigure { error })
                    .map(move |_| (group_id, req))
            })
            .and_then(move |(group_id, mut req)| {
                // cross-VM talk
                req.from_port = Some(0);
                req.to_port = Some(65535);
                req.cidr_ip = Some("172.31.0.0/16".to_string());
                trace!(log, "adding internal VM access to security group");
                ec2.authorize_security_group_ingress(&req)
                    .map_err(|error| TsunamiError::SecurityGroupConfigure { error })
                    .map(move |_| group_id)
            });

        Box::new(future)
    }

    fn configure_ssh<'a>(
        log: &'a slog::Logger,
        ec2: &'a Box<rusoto_ec2::Ec2>,
    ) -> Box<Future<Item = (String, String), Error = TsunamiError> + 'a> {
        // construct keypair for ssh access
        trace!(log, "creating keypair");
        let mut req = rusoto_ec2::CreateKeyPairRequest::default();
        let mut key_name = String::from("tsunami_key_");
        key_name.extend(rand::thread_rng().gen_ascii_chars().take(10));
        req.key_name = key_name.clone();
        let future = ec2.create_key_pair(&req)
            .map_err(|error| TsunamiError::KeyPair { error })
            .map(move |keypair| {
                trace!(log, "created keypair"; "fingerprint" => keypair.key_fingerprint);
                let pk = keypair
                    .key_material
                    .expect("aws did not generate key material for new key");
                (pk, key_name)
            });

        Box::new(future)
    }

    fn configure_placement_groups(
        log: &slog::Logger,
        ec2: &Box<rusoto_ec2::Ec2>,
    ) -> Box<Future<Item = Option<rusoto_ec2::SpotPlacement>, Error = TsunamiError>> {
        // determine a placement if the user has requested one
        trace!(log, "creating placement group");
        let mut req = rusoto_ec2::CreatePlacementGroupRequest::default();
        let mut placement_name = String::from("tsunami_placement_");
        placement_name.extend(rand::thread_rng().gen_ascii_chars().take(10));
        req.group_name = placement_name.clone();
        req.strategy = String::from("cluster");

        let log = log.clone();
        let future = ec2.create_placement_group(&req)
            .map_err(|error| TsunamiError::PlacementGroups { error })
            .map(move |_| {
                trace!(log, "created placement group");

                let mut placement = rusoto_ec2::SpotPlacement::default();
                placement.group_name = Some(placement_name);
                Some(placement)
            });

        Box::new(future)
    }

    fn issue_spot_requests<'a>(
        log: &'a slog::Logger,
        ec2: &'a Box<rusoto_ec2::Ec2>,
        descriptors: &'a HashMap<String, (MachineSetup, u32)>,
        max_duration: i64,
        placement: Option<rusoto_ec2::SpotPlacement>,
        key_name: String,
        group_id: String,
    ) -> Box<Future<Item = SpotRequestResult<'a>, Error = TsunamiError> + 'a> {
        debug!(log, "issuing spot requests");

        let all: Vec<_> = descriptors
            .iter()
            .map(|(name, &(ref setup, number))| {
                let name = &**name;

                let mut launch = rusoto_ec2::RequestSpotLaunchSpecification::default();
                launch.image_id = Some(setup.ami.clone());
                launch.instance_type = Some(setup.instance_type.clone());
                launch.placement = placement.clone();

                launch.security_group_ids = Some(vec![group_id.clone()]);
                launch.key_name = Some(key_name.clone());

                let setup_fn = &setup.setup;
                let user = &*setup.username;

                // TODO: VPC

                let req = rusoto_ec2::RequestSpotInstancesRequest {
                    instance_count: Some(i64::from(number)),
                    block_duration_minutes: Some(max_duration),
                    launch_specification: Some(launch),
                    // one-time spot instances are only fulfilled once and therefore do not need to be
                    // cancelled.
                    type_: Some("one-time".into()),
                    ..Default::default()
                };

                trace!(log, "issuing spot request for {}", name; "#" => number);
                ec2.request_spot_instances(&req)
                    .map_err(move |error| TsunamiError::RequestSpotInstances {
                        name: name.into(),
                        error,
                    })
                    .map(move |v| (v, name))
                    .map(|(res, name)| {
                        (
                            res.spot_instance_requests.expect(
                                "request_spot_instances should always \
                                 return spot instance requests",
                            ),
                            name,
                        )
                    })
                    .map(move |(res, name)| (name, setup_fn, user, res))
            })
            .collect();

        let future = future::join_all(all).map(move |res_v| {
            let mut result = SpotRequestResult::default();
            for (name, setup, user, res) in res_v {
                result.setup_fns.insert(name, setup);
                result.usernames.insert(name, user);
                for sir in res {
                    if let Some(sir) = sir.spot_instance_request_id {
                        trace!(log, "activated spot request"; "id" => &sir);
                        result.id_to_name.insert(sir.clone(), name.into());
                        result.spot_req_ids.push(sir);
                    }
                }
            }

            result
        });

        Box::new(future)
    }

    fn wait_for_instances<'a>(
        log: &'a slog::Logger,
        ec2: &'a Box<rusoto_ec2::Ec2>,
        spot_req_ids: Vec<String>,
        id_to_name: HashMap<String, &'a str>,
        max_wait: Option<time::Duration>,
    ) -> Box<Future<Item = (HashMap<&'a str, Vec<Machine>>, Vec<String>), Error = TsunamiError> + 'a>
    {
        // Helper enum for intermediate state
        enum RunningInstanceSet<'a> {
            /// All instances started correctly: holds instance ids and id_to_name
            All(Vec<String>, HashMap<String, &'a str>),
            /// Some instances were not started: holds instance ids for those that were
            Only(Vec<String>),
        }

        let mut req = rusoto_ec2::DescribeSpotInstanceRequestsRequest::default();
        req.spot_instance_request_ids = Some(spot_req_ids.clone());

        debug!(log, "waiting for instances to spawn");
        let wait_for_instances = future::loop_fn(id_to_name, move |mut id_to_name| {
            trace!(log, "checking spot request status");

            ec2.describe_spot_instance_requests(&req)
                .then(move |res| {
                    if let Err(e) = res {
                        let msg = format!("{}", e);
                        if msg.contains("The spot instance request ID")
                            && msg.contains("does not exist")
                        {
                            trace!(log, "spot instance requests not yet ready");
                            return Ok(future::Loop::Continue(id_to_name));
                        } else {
                            return Err(TsunamiError::Describe);
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
                                trace!(log, "spot request ready"; "state" => state, "id" => &sir.spot_instance_request_id);
                                false
                            }
                        });

                    if !any_pending {
                        // unwraps okay because they are the same as expects above
                        let mut iid_to_name = HashMap::new();
                        let v: Vec<_> = res.spot_instance_requests
                            .unwrap()
                            .into_iter()
                            .filter_map(|sir| {
                                let id = sir.spot_instance_request_id
                                    .expect("spot request must have spot request id");
                                let name = id_to_name
                                    .remove(&*id)
                                    .clone()
                                    .expect("every spot request id is made for some machine set");

                                if sir.state.as_ref().unwrap() == "active" {
                                    // unwrap ok because active implies instance_id.is_some()
                                    // because !any_pending
                                    let instance_id = sir.instance_id.unwrap();
                                    trace!(log, "spot request satisfied"; "set" => &name, "iid" => &instance_id);
                                    iid_to_name.insert(instance_id.clone(), name);

                                    Some(instance_id)
                                } else {
                                    error!(log, "spot request failed: {:?}", &sir.status; "set" => &name, "state" => &sir.state.unwrap());
                                    None
                                }
                            })
                            .collect();
                        Ok(future::Loop::Break(RunningInstanceSet::All(v, iid_to_name)))
                    } else {
                        // TODO: sleep here
                        Ok(future::Loop::Continue(id_to_name))
                    }
                })
                .and_then(|r| match r {
                    future::Loop::Continue(i2n) => Either::A(
                        tokio_timer::Delay::new(
                            time::Instant::now() + time::Duration::from_millis(500),
                        ).map(move |_| future::Loop::Continue(i2n))
                            .map_err(|error| TsunamiError::Timer { error }),
                    ),
                    b => Either::B(future::ok(b)),
                })
        });

        let future = if let Some(wait_limit) = max_wait {
            let future = tokio_timer::Deadline::new(
                wait_for_instances,
                time::Instant::now() + wait_limit,
            ).map_err(|timer_error| timer_error.into_inner())
                .or_else(move |e| {
                    match e {
                        None => {
                            warn!(log, "wait time exceeded -- cancelling run");
                            let mut cancel =
                                rusoto_ec2::CancelSpotInstanceRequestsRequest::default();
                            cancel.spot_instance_request_ids = spot_req_ids.clone();

                            let future = ec2.cancel_spot_instance_requests(&cancel)
                                .map_err(|error| TsunamiError::Cancel { error })
                                .map_err(move |e| {
                                    warn!(log, "failed to cancel spot instance request: {:?}", e);
                                    e
                                })
                                .and_then(move |_| {
                                    trace!(
                                        log,
                                        "spot instances cancelled -- gathering remaining instances"
                                    );

                                    // wait for a little while for the cancelled spot requests to settle
                                    // and any that were *just* made active to be associated with their instances
                                    tokio_timer::Delay::new(
                                        time::Instant::now() + time::Duration::from_secs(1),
                                    ).map_err(|error| TsunamiError::Timer { error })
                                })
                                .and_then(move |_| {
                                    let mut req =
                                        rusoto_ec2::DescribeSpotInstanceRequestsRequest::default();
                                    req.spot_instance_request_ids = Some(spot_req_ids);

                                    ec2.describe_spot_instance_requests(&req).map_err(|error| {
                                        TsunamiError::FindAfterCancellation { error }
                                    })
                                })
                                .map(move |res| {
                                    let instances = res.spot_instance_requests
                                        .map(move |reqs| {
                                            reqs.into_iter()
                                                .filter_map(move |mut sir| {
                                                    sir.instance_id
                                                        .take()
                                                        .map(|instance_id| {
                                                            trace!(log, "spot request cancelled"; "iid" => &instance_id);
                                                            instance_id
                                                        })
                                                        .or_else(|| {
                                                            error!(
                                                                log,
                                                                "spot request failed: {:?}",
                                                                &sir.status
                                                            );
                                                            None
                                                        })
                                                })
                                                .collect::<Vec<_>>()
                                        })
                                        .unwrap_or_default();
                                    RunningInstanceSet::Only(instances)
                                });
                            Either::A(future)
                        }
                        Some(e) => Either::B(future::err(e)),
                    }
                });
            Either::A(future)
        } else {
            Either::B(wait_for_instances)
        }.and_then(|wait_result| match wait_result {
            RunningInstanceSet::All(instances, id_to_name) => {
                Either::A(future::ok((id_to_name, instances)))
            }
            RunningInstanceSet::Only(instances) => {
                Either::B(future::err(TsunamiError::Timeout { instances }))
            }
        })
            .and_then(move |(id_to_name, instances)| {
                // 3. wait until all instances are up
                // note that we *don't* do this check if we have no instances, b/c empty instance list
                // means "list all instances".
                let mut desc_req = rusoto_ec2::DescribeInstancesRequest::default();
                let term_instances = instances.clone();
                desc_req.instance_ids = Some(instances);

                future::loop_fn(id_to_name, move |id_to_name| {
                    ec2.describe_instances(&desc_req).map(move |reservations| {
                        let mut machines = HashMap::new();
                        for reservation in reservations.reservations.unwrap_or_else(Vec::new) {
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
                                        let name = id_to_name[&instance_id];
                                        let machine = Machine {
                                            ssh: None,
                                            instance_type,
                                            private_ip,
                                            public_ip,
                                            public_dns,
                                        };

                                        trace!(log, "instance ready"; "set" => &name, "ip" => &machine.public_ip);
                                        machines.entry(name).or_insert_with(Vec::new).push(machine);
                                    }
                                    _ => {
                                        return future::Loop::Continue(id_to_name);
                                    }
                                }
                            }
                        }

                        future::Loop::Break(machines)
                    })
                }).then(|r| match r {
                    Ok(machine) => Ok((machine, term_instances)),
                    Err(error) => Err(TsunamiError::DescribeWithInstances {
                        error,
                        instances: term_instances,
                    }),
                })
            });

        Box::new(future)
    }

    fn setup_and_run<'a, F, FF>(
        log: &'a slog::Logger,
        machines: HashMap<&'a str, Vec<Machine>>,
        setup_fns: HashMap<
            &'a str,
            &'a Box<Fn(&mut ssh::Session) -> Box<Future<Item = (), Error = Error>>>,
        >,
        usernames: HashMap<&'a str, &'a str>,
        pk: String,
        expected_num: u32,
        handle: &'a tokio_core::reactor::Handle,
        f: F,
    ) -> Box<Future<Item = (), Error = Error> + 'a>
    where
        F: 'a + FnOnce(HashMap<&'a str, Vec<Machine>>) -> FF,
        FF: 'a + IntoFuture<Item = (), Error = Error>,
    {
        let running: u32 = machines.values().map(|ms| ms.len() as u32).sum();
        if running != expected_num {
            crit!(
                log,
                "only {} out of {} machines were started; aborting",
                running,
                expected_num
            );
            return Box::new(future::err(format_err!(
                "only {} out of {} machines were started; aborting",
                running,
                expected_num
            )));
        }

        info!(log, "all machines instantiated; running setup");

        //    - once an instance is ready, run setup closure
        let private_key = &pk;
        let setups: Vec<_> = machines
            .into_iter()
            .flat_map(|(name, machines)| {
                let setup_fn = setup_fns[name];
                let username = usernames[name];

                machines.into_iter().map(move |machine| {
                    use std::net::{IpAddr, SocketAddr};

                    let addr = machine
                        .public_ip
                        .parse::<IpAddr>()
                        .expect("machine ip is not an ip address");
                    let public_dns = machine.public_dns.clone();

                    ssh::Session::connect(username, SocketAddr::new(addr, 22), private_key, handle)
                        .then(move |r| {
                            let r = r.context(format!(
                                "failed to ssh to {} machine {}",
                                name, &machine.public_dns
                            ));

                            if r.is_err() {
                                error!(log, "failed to ssh to {}:{}", name, &public_dns);
                            }

                            r.map(move |ssh| (machine, ssh))
                        })
                        .and_then(move |(machine, mut ssh)| {
                            debug!(log, "setting up {} instance", name; "dns" => &machine.public_dns);
                            setup_fn(&mut ssh).map(move |_| ssh).then(move |r| {
                                let r = r.context(format!(
                                    "setup procedure for {} machine failed",
                                    name
                                ));

                                if r.is_err() {
                                    error!(log, "setup for {} machine failed", name);
                                }

                                r.map(move |ssh| (machine, ssh))
                            })
                        })
                        .map(move |(mut machine, ssh)| {
                            info!(log, "finished setting up {} instance", name; "dns" => &machine.public_dns);
                            machine.ssh = Some(ssh);
                            (name, machine)
                        })
                })
            })
            .collect();

        let future = future::join_all(setups)
            .map_err(Error::from)
            .and_then(move |machines| {
                let machines = machines.into_iter().fold(
                    HashMap::new(),
                    |mut machines, (name, machine)| {
                        machines.entry(name).or_insert_with(Vec::new).push(machine);
                        machines
                    },
                );
                // 4. invoke F with Machine descriptors
                let start = time::Instant::now();
                info!(log, "quiet before the storm");
                f(machines)
                    .into_future()
                    .then(|r| r.context("tsunami main routine failed"))
                    .map_err(move |e| {
                        crit!(log, "main tsunami routine failed");
                        Error::from(e)
                    })
                    .map(move |_| start)
            })
            .map(move |start| {
                info!(log, "the power of the tsunami was unleashed"; "duration" => start.elapsed().as_secs());
                ()
            });

        Box::new(future)
    }

    fn clean_up<'a>(
        log: &'a slog::Logger,
        ec2: &'a Box<rusoto_ec2::Ec2>,
        result: Result<Vec<String>, TsunamiError>,
    ) -> Box<Future<Item = (), Error = Error> + 'a> {
        match result {
            Ok(instances) => Box::new(Self::terminate_instances(log, ec2, instances)),
            Err(error) => {
                if let Some(instances) = error.get_term_instances() {
                    // TODO: include possible error from terminate_instances?
                    Box::new(
                        Self::terminate_instances(log, ec2, instances)
                            .then(|_| future::err(Error::from(error))),
                    )
                } else {
                    Box::new(future::err(Error::from(error)))
                }
            }
        }
    }

    fn terminate_instances<'a>(
        log: &'a slog::Logger,
        ec2: &'a Box<rusoto_ec2::Ec2>,
        term_instances: Vec<String>,
    ) -> Box<Future<Item = (), Error = Error> + 'a> {
        // 5. terminate all instances
        if term_instances.is_empty() {
            return Box::new(future::ok(()));
        }

        debug!(log, "terminating instances");

        let mut termination_req = rusoto_ec2::TerminateInstancesRequest::default();
        termination_req.instance_ids = term_instances;

        let future = ec2.terminate_instances(&termination_req)
            .map_err(move |term_e| {
                warn!(log, "failed to terminate tsunami instances: {:?}", term_e);
                Error::from(term_e)
            })
            .map(|_| ());

        Box::new(future)

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
        // TODO: clean up created placement group
        */
    }
}
