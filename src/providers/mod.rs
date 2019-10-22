use failure::Error;
use std::collections::HashMap;

pub struct LaunchDescriptor<M: MachineSetup> {
    pub region: M::Region,
    pub log: slog::Logger,
    pub max_wait: Option<std::time::Duration>,
    pub machines: Vec<(String, M)>,
}

/// This is used to group machines into connections
/// to cloud providers. e.g., for AWS we need a separate
/// connection to each region.
pub trait MachineSetup {
    type Region: Eq + std::hash::Hash + Clone + ToString;
    fn region(&self) -> Self::Region;
}

/// Implement this trait to implement a new cloud provider for Tsunami.
/// Tsunami will call `launch` once per unique region, as defined by `MachineSetup`.
pub trait Launcher {
    type MachineDescriptor: MachineSetup;

    /// Spawn the instances. Implementors should remember enough information to subsequently answer
    /// calls to `connect_instances`, i.e., the IPs of the machines.
    fn launch(&mut self, desc: LaunchDescriptor<Self::MachineDescriptor>) -> Result<(), Error>;

    /// Return connections to the [`Machine`s](crate::Machine) that `launch` spawned.
    fn connect_all<'l>(&'l self) -> Result<HashMap<String, crate::Machine<'l>>, Error>;
}

macro_rules! collect {
    ($x: expr) => {{
        $x.values()
            .map(|r| r.connect_all())
            .fold(Ok(HashMap::default()), |acc, el| {
                acc.and_then(|mut a| {
                    a.extend(el?.into_iter());
                    Ok(a)
                })
            })
    }};
}

struct Sep(&'static str);

impl Default for Sep {
    fn default() -> Self {
        Sep("_")
    }
}

impl From<&'static str> for Sep {
    fn from(s: &'static str) -> Self {
        Sep(s)
    }
}

fn rand_name(prefix: &str) -> String {
    rand_name_sep(prefix, "_")
}

fn rand_name_sep(prefix: &str, sep: impl Into<Sep>) -> String {
    use rand::Rng;
    let rng = rand::thread_rng();

    let sep = sep.into();

    let mut name = format!("tsunami{}{}{}", sep.0, prefix, sep.0);
    name.extend(rng.sample_iter(&rand::distributions::Alphanumeric).take(10));
    name
}

pub mod aws;
pub mod azure;
pub mod baremetal;

fn setup_machine(
    log: &slog::Logger,
    nickname: &str,
    pub_ip: &str,
    username: &str,
    max_wait: Option<std::time::Duration>,
    private_key: Option<&std::path::Path>,
    f: &dyn Fn(&mut crate::ssh::Session, &slog::Logger) -> Result<(), Error>,
) -> Result<(), Error> {
    use crate::ssh;
    use failure::ResultExt;
    use std::net::{IpAddr, SocketAddr};

    let mut sess = ssh::Session::connect(
        log,
        username,
        SocketAddr::new(
            pub_ip
                .parse::<IpAddr>()
                .context("machine ip is not an ip address")?,
            22,
        ),
        private_key,
        max_wait,
    )
    .context(format!("failed to ssh to machine {}", nickname))
    .map_err(|e| {
        error!(log, "failed to ssh to {}", pub_ip);
        e
    })?;

    debug!(log, "setting up instance"; "ip" => &pub_ip);
    f(&mut sess, log)
        .context(format!("setup procedure for {} machine failed", &nickname))
        .map_err(|e| {
            error!(
            log,
            "machine setup failed";
            "name" => &nickname,
            "ssh" => format!("ssh ubuntu@{}", &pub_ip),
            );
            e
        })?;
    info!(log, "finished setting up instance"; "name" => &nickname, "ip" => &pub_ip);
    Ok(())
}
