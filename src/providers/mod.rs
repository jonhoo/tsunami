//! Implements backend functionality to spawn machines.

use color_eyre::Report;
use eyre::WrapErr;
use itertools::Itertools;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use tracing::instrument;
use tracing_futures::Instrument;

/// A description of a set of machines to launch.
///
/// The machines are constrained to a single `region`.
#[derive(Debug)]
pub struct LaunchDescriptor<M: MachineSetup + Send> {
    /// The region to launch into.
    pub region: M::Region,
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
    type Region: Eq + std::hash::Hash + Clone + std::fmt::Display + Send;
    /// Get the region.
    fn region(&self) -> Self::Region;
}

/// Use this trait to implement support for launching machines in a cloud provider.
///
/// If you just want to launch machines, use [`crate::Tsunami`] instead of this trait.
pub trait Launcher: Send {
    /// A type describing a single instance to launch.
    type MachineDescriptor: MachineSetup + Send;

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
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'l>>;

    /// Return connections to the [`Machine`s](crate::Machine) that `launch` spawned.
    fn connect_all<'l>(
        &'l self,
    ) -> Pin<
        Box<dyn Future<Output = Result<HashMap<String, crate::Machine<'l>>, Report>> + Send + 'l>,
    >;

    /// Shut down all instances.
    fn terminate_all(self) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send>>;

    /// Helper method to group `MachineDescriptor`s into regions and call `launch`.
    ///
    /// This implementation initializes each region serially. It may be useful for performance to
    /// provide an implementation that initializes the regions concurrently.
    #[instrument(skip(self, max_wait))]
    fn spawn<'l, I>(
        &'l mut self,
        descriptors: I,
        max_wait: Option<std::time::Duration>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'l>>
    where
        I: IntoIterator<Item = (String, Self::MachineDescriptor)> + Send + 'static,
        I: std::fmt::Debug,
        I::IntoIter: Send,
    {
        Box::pin(
            async move {
                let max_wait = max_wait;

                tracing::info!("spinning up tsunami");

                for (region_name, setups) in descriptors
                    .into_iter()
                    .map(|(name, setup)| (setup.region(), (name, setup)))
                    .into_group_map()
                {
                    let region_span = tracing::debug_span!("region", region = %region_name);
                    let dsc = LaunchDescriptor {
                        region: region_name.clone(),
                        max_wait,
                        machines: setups,
                    };

                    self.launch(dsc).instrument(region_span).await?;
                }

                Ok(())
            }
            .in_current_span(),
        )
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
                .collect::<Result<Vec<_>, Report>>()?;

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
#[instrument(skip(max_wait, private_key, f))]
async fn setup_machine(
    nickname: &str,
    pub_ip: &str,
    username: &str,
    max_wait: Option<std::time::Duration>,
    private_key: Option<&std::path::Path>,
    f: &(dyn for<'r> Fn(
        &'r crate::Machine<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'r>>
          + Send
          + Sync),
) -> Result<(), Report> {
    let m = crate::MachineDescriptor {
        nickname: Default::default(),
        public_dns: pub_ip.to_string(),
        public_ip: pub_ip.to_string(),
        private_ip: None,
        _tsunami: Default::default(),
    };

    let mut m = m.connect_ssh(username, private_key, max_wait, 22).await?;

    tracing::debug!("setting up instance");
    f(&mut m).await.wrap_err("setup procedure failed")?;
    tracing::info!("instance ready");
    Ok(())
}
