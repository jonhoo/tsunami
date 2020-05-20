//! Implements backend functionality to spawn machines.

use failure::Error;
use itertools::Itertools;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

/// A description of a set of machines to launch.
///
/// The machines are constrained to a single `region`.
#[derive(Debug)]
pub struct LaunchDescriptor<M: MachineSetup> {
    /// The region to launch into.
    pub region: M::Region,
    /// A logger.
    pub log: slog::Logger,
    /// An optional timeout.
    ///
    /// If specified and the LaunchDescriptor is not launched in the given time,
    /// [`crate::TsunamiBuilder::spawn`] will fail with an error.
    pub max_wait: Option<std::time::Duration>,
    /// The machines to launch.
    pub machines: Vec<(String, M)>,
}

/// This is used to group machines into connections
/// to cloud providers. e.g., for AWS we need a separate
/// connection to each region.
pub trait MachineSetup {
    /// Grouping type.
    type Region: Eq + std::hash::Hash + Clone + ToString;
    /// Get the region.
    fn region(&self) -> Self::Region;
}

/// Use this trait to implement support for launching machines in a cloud provider.
///
/// If you just want to launch machines, use [`crate::Tsunami`] instead of this trait.
pub trait Launcher {
    /// A type describing a single instance to launch.
    type MachineDescriptor: MachineSetup;

    /// Spawn the instances.
    ///
    /// Implementations can assume that all the entries in `desc` are for the same region.
    ///
    /// Implementors should remember enough information to subsequently answer
    /// calls to `connect_all`, i.e., the IPs of the machines.
    ///
    /// This method can be called multiple times. Subsequent calls to
    /// `connect_all` should return the new machines as well as any previously
    /// spawned machines.
    fn launch<'l>(
        &'l mut self,
        desc: LaunchDescriptor<Self::MachineDescriptor>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + 'l>>;

    /// Return connections to the [`Machine`s](crate::Machine) that `launch` spawned.
    fn connect_all<'l>(
        &'l self,
    ) -> Pin<Box<dyn Future<Output = Result<HashMap<String, crate::Machine<'l>>, Error>> + 'l>>;

    /// Shut down all instances.
    fn cleanup(self) -> Pin<Box<dyn Future<Output = Result<(), Error>>>>;

    /// Helper method to group `MachineDescriptor`s into regions and call `launch`.
    ///
    /// This implementation initializes each region serially. It may be useful for performance to
    /// provide an implementation that initializes the regions concurrently.
    fn spawn<'l>(
        &'l mut self,
        descriptors: impl IntoIterator<Item = (String, Self::MachineDescriptor)> + 'static,
        max_wait: Option<std::time::Duration>,
        log: Option<slog::Logger>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + 'l>> {
        Box::pin(async move {
            let max_wait = max_wait;
            let log = log.unwrap_or_else(|| slog::Logger::root(slog::Discard, o!()));

            info!(log, "spinning up tsunami");

            for (region_name, setups) in descriptors
                .into_iter()
                .map(|(name, setup)| (setup.region(), (name, setup)))
                .into_group_map()
            {
                let region_log = log.new(slog::o!("region" => region_name.clone().to_string()));
                let dsc = LaunchDescriptor {
                    region: region_name.clone(),
                    log: region_log,
                    max_wait,
                    machines: setups,
                };

                self.launch(dsc).await?;
            }

            Ok(())
        })
    }
}

// The aws and azure implementations use this helper macro, so it has to be declared before the
// module declarations.
#[cfg(any(feature = "aws", feature = "azure"))]
macro_rules! collect {
    ($x: expr) => {{
        Ok({
            let mps = futures_util::future::join_all($x.values().map(|r| r.connect_all()))
                .await
                .into_iter()
                .collect::<Result<Vec<_>, Error>>()?;

            mps.into_iter().flat_map(|x| x.into_iter()).collect()
        })
    }};
}

#[cfg(feature = "aws")]
pub mod aws;
#[cfg(feature = "azure")]
pub mod azure;
#[cfg(feature = "baremetal")]
pub mod baremetal;

#[cfg(any(feature = "aws", feature = "azure"))]
struct Sep(&'static str);

#[cfg(any(feature = "aws", feature = "azure"))]
impl Default for Sep {
    fn default() -> Self {
        Sep("_")
    }
}

#[cfg(any(feature = "aws", feature = "azure"))]
impl From<&'static str> for Sep {
    fn from(s: &'static str) -> Self {
        Sep(s)
    }
}

#[cfg(any(feature = "aws", feature = "azure"))]
fn rand_name(prefix: &str) -> String {
    rand_name_sep(prefix, "_")
}

#[cfg(any(feature = "aws", feature = "azure"))]
fn rand_name_sep(prefix: &str, sep: impl Into<Sep>) -> String {
    use rand::Rng;
    let rng = rand::thread_rng();

    let sep = sep.into();

    let mut name = format!("tsunami{}{}{}", sep.0, prefix, sep.0);
    name.extend(rng.sample_iter(&rand::distributions::Alphanumeric).take(10));
    name
}

#[cfg(any(feature = "aws", feature = "azure"))]
async fn setup_machine(
    log: &slog::Logger,
    nickname: &str,
    pub_ip: &str,
    username: &str,
    max_wait: Option<std::time::Duration>,
    private_key: Option<&std::path::Path>,
    f: &dyn for<'r> Fn(
        &'r mut crate::ssh::Session,
        &'r slog::Logger,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'r>>,
) -> Result<(), Error> {
    use failure::ResultExt;

    let mut m = crate::Machine {
        nickname: Default::default(),
        public_dns: pub_ip.to_string(),
        public_ip: pub_ip.to_string(),
        private_ip: None,
        ssh: None,
        _tsunami: Default::default(),
    };

    m.connect_ssh(log, username, private_key, max_wait, 22)
        .await?;
    let mut sess = m.ssh.unwrap();

    debug!(log, "setting up instance"; "ip" => &pub_ip);
    f(&mut sess, log)
        .await
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
