//! `tsunami` provides an interface for running short-lived jobs and experiments on EC2 spot block
//! instances. Most interaction with this library happens through
//! [`TsunamiBuilder`](struct.TsunamiBuilder.html).
//!
//! # Live-coding
//!
//! The crate is under development as part of a live-coding stream series intended for users who
//! are already somewhat familiar with Rust, and who want to see something larger and more involved
//! be built. You can find the recordings of past sessions [on
//! YouTube](https://www.youtube.com/playlist?list=PLqbS7AVVErFgY2faCIYjJZv_RluGkTlKt).

#[macro_use]
extern crate failure;
extern crate rand;
extern crate rayon;
extern crate rusoto_core;
extern crate rusoto_ec2;
#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate ssh2;
extern crate tempfile;

use failure::{Error, ResultExt};
use itertools::Itertools;
use rayon::prelude::*;
use rusoto_core::DefaultCredentialsProvider;
use rusoto_core::Region;
use std::collections::HashMap;
use std::time;

mod ssh;
pub use ssh::Session;

pub mod aws_region;
use aws_region::AWSRegion;

/// A handle to an instance currently running as part of a tsunami.
#[derive(Default)]
pub struct Machine {
    pub nickname: String,
    pub instance_id: String,

    /// If `Some(_)`, an established SSH session to this host.
    pub ssh: Option<ssh::Session>,

    /// AWS EC2 instance type hosting this machine.
    /// See https://aws.amazon.com/ec2/instance-types/ for details.
    pub instance_type: String,

    /// The private IP address of this host on its designated VPC.
    pub private_ip: String,

    pub public_dns: String,
    pub public_ip: String,
}

struct UbuntuAmi(String);

impl From<Region> for UbuntuAmi {
    fn from(r: Region) -> Self {
        // https://cloud-images.ubuntu.com/locator/
        // ec2 20190814 releases
        UbuntuAmi(
            match r {
                Region::ApEast1 => "ami-e0ff8491",
                Region::ApNortheast1 => "ami-0cb1c8cab7f5249b6",
                Region::ApNortheast2 => "ami-081626bfb3fbc9f49",
                Region::ApSouth1 => "ami-0cf8402efdb171312",
                Region::ApSoutheast1 => "ami-099d318f80eab7e94",
                Region::ApSoutheast2 => "ami-08a648fb5cc86fb74",
                Region::CaCentral1 => "ami-0bc1dd4eb012a451e",
                Region::EuCentral1 => "ami-0cdab515472ca0bac",
                Region::EuNorth1 => "ami-c37bf0bd",
                Region::EuWest1 => "ami-01cca82393e531118",
                Region::EuWest2 => "ami-0a7c91b6616d113b1",
                Region::EuWest3 => "ami-033e0056c336ecff0",
                Region::SaEast1 => "ami-094c359b4d8c6a8ca",
                Region::UsEast1 => "ami-064a0193585662d74",
                Region::UsEast2 => "ami-021b7b04f1ac696c2",
                Region::UsWest1 => "ami-056d04da775d124d7",
                Region::UsWest2 => "ami-09a3d8a7177216dcf",
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

/// A template for a particular machine setup in a tsunami.
/// Define a new template for a tsunami machine setup.
pub struct MachineSetup {
    region: Region,
    instance_type: String,
    ami: String,
    setup: Option<Box<dyn Fn(&mut ssh::Session, &slog::Logger) -> Result<(), Error> + Sync>>,
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
        setup: impl Fn(&mut ssh::Session, &slog::Logger) -> Result<(), Error> + Sync + 'static,
    ) -> Self {
        self.setup = Some(Box::new(setup));
        self
    }
}

/// Use this to prepare and execute a new tsunami.
///
/// availability_zone: Set up the machine in a specific EC2 availability zone.
/// This controls the `availability_zone` field of the
/// [`SpotPlacement`](https://rusoto.github.io/rusoto/rusoto_ec2/struct.SpotPlacement.html)
/// struct (N.B.: even though the documentation claims that the parameter only affects spot
/// fleets, it does appear to affect *all* spot instances).
///
/// A tsunami consists of one or more [`MachineSetup`](struct.MachineSetup.html)s that will be
/// spawned as EC2 spot instances. See
/// [`TsunamiBuilder#add_set`](struct.TsunamiBuilder.html#method.add_set)) for how to construct a
/// tsunami.
#[must_use]
pub struct TsunamiBuilder {
    descriptors: HashMap<String, MachineSetup>,
    log: slog::Logger,
    max_duration: i64,
    max_wait: Option<time::Duration>,
}

impl Default for TsunamiBuilder {
    fn default() -> Self {
        TsunamiBuilder {
            descriptors: Default::default(),
            log: slog::Logger::root(slog::Discard, o!()),
            max_duration: 360, // 6 hours
            max_wait: None,
        }
    }
}

impl TsunamiBuilder {
    pub fn add(&mut self, nickname: String, m: MachineSetup) {
        self.descriptors.insert(nickname, m);
    }

    /// Limit how long we should wait for instances to be available before giving up.
    ///
    /// This includes both waiting for spot requests to be satisfied, and for SSH connections to be
    /// established. Defaults to no limit.
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
    /// The default duration is 6 hours.
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

    /// When all instances are up and running, the given closure will be called with a handle to
    /// all spawned hosts. When the closure exits, the instances are all terminated automatically.
    pub fn run<F, R>(self, pause: bool, f: F) -> Result<R, Error>
    where
        F: FnOnce(HashMap<String, Machine>, &slog::Logger) -> Result<R, Error>,
    {
        let TsunamiBuilder {
            descriptors,
            log,
            max_duration,
            max_wait,
        } = self;
        let log = &log;

        // initialize the set of unique regions to connect to.
        let regions: Result<HashMap<String, AWSRegion>, Error> = descriptors
            .iter()
            .map(|(_, desc)| desc.region.name())
            .unique()
            .map(|region| {
                let region_log = log.new(slog::o!("region" => format!("{:?}", region)));
                let provider = DefaultCredentialsProvider::new()?;
                let ec2 = AWSRegion::new(
                    region.parse().expect("Didn't get valid region"),
                    provider,
                    region_log,
                )?;
                Ok((region.to_string(), ec2))
            })
            .collect();
        let mut regions = regions?; // collect can't infer the types correctly, so do this separately

        info!(log, "spinning up tsunami");
        let expected_num: u32 = descriptors.len() as u32;

        // 1. issue spot requests
        debug!(log, "issuing spot requests");
        // TODO: issue spot requests in parallel

        let mut region_map = HashMap::new();
        for (reg_name, (name, m)) in descriptors
            .into_iter()
            .map(|(nickname, m)| (m.region.name().to_string(), (nickname, m)))
        {
            region_map
                .entry(reg_name)
                .or_insert_with(Vec::new)
                .push((name, m));
        }

        for (region, machines) in region_map {
            trace!(log, "Spot instance requests"; "region" => &region);
            regions
                .get_mut(&region)
                .expect(&format!("Couldn't find region {}", region))
                .make_spot_instance_requests(max_duration, machines)?;
        }

        // 2. wait for spot requests to complete
        for (_, region) in regions.iter_mut() {
            region.wait_for_spot_instance_requests(self.max_wait)?;
        }

        // 3. wait until all instances are up
        // note that we *don't* do this check if we have no instances, b/c empty instance list
        // means "list all instances".
        let machines: Result<Vec<HashMap<String, Machine>>, Error> = regions
            .par_iter_mut()
            .map(|(_, region)| region.wait_for_instances(max_wait))
            .collect();
        // TODO collect all the errors, not just the first one
        let machines: HashMap<String, Machine> = machines?.into_iter().flat_map(|x| x).collect();

        let mut res = None;
        let running = machines.len() as u32;
        if running == expected_num {
            // 4. invoke F with Machine descriptors
            let start = time::Instant::now();
            info!(log, "quiet before the storm");
            res = Some(
                f(machines, log)
                    .context("tsunami main routine failed")
                    .map_err(|e| {
                        crit!(log, "main tsunami routine failed");
                        println!("{}", e);
                        wait_for_continue(log);
                        e
                    })?,
            );
            info!(log, "the power of the tsunami was unleashed"; "duration" => start.elapsed().as_secs());
        } else {
            crit!(
                log,
                "only {} out of {} machines were started; aborting",
                running,
                expected_num
            );
        }

        debug!(log, "all done");
        if pause {
            wait_for_continue(log);
        }

        res.ok_or_else(|| format_err!("no result from main()"))
    }
}

fn wait_for_continue(log: &slog::Logger) {
    debug!(
        log,
        "pausing for manual instance inspection, press enter to continue"
    );

    use std::io::prelude::*;
    let stdin = std::io::stdin();
    let mut iterator = stdin.lock().lines();
    iterator.next().unwrap().unwrap();
}
