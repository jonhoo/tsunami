use failure::Error;
use std::collections::HashMap;

/// This is used to group machines into connections
/// to cloud providers. e.g., for AWS we need a separate
/// connection to each region.
pub trait MachineSetup {
    type Region: Eq + std::hash::Hash + Clone + std::string::ToString;
    fn region(&self) -> Self::Region;
}

/// Implement this trait to implement a new cloud provider for Tsunami.
/// Tsunami will call `init_instances` once per unique region, as defined by `MachineSetup`.
pub trait Launcher: Drop + Send + Sync + Sized {
    type Region: Send + Eq + std::hash::Hash + Clone + std::string::ToString;
    type Machine: MachineSetup<Region = Self::Region> + Send;

    fn init(log: slog::Logger, r: Self::Region) -> Result<Self, Error>;
    fn region(&self) -> Self::Region;

    /// Spawn the instances. Implementors should remember enough information to subsequently answer
    /// calls to `connect_instances`, i.e., the IPs of the machines.
    fn init_instances(
        &mut self,
        max_instance_duration: Option<std::time::Duration>,
        max_wait: Option<std::time::Duration>,
        machines: impl IntoIterator<Item = (String, Self::Machine)>,
    ) -> Result<(), Error>;

    /// Return connections to the [`Machine`s](crate::Machine) that `init_instances` spawned.
    fn connect_instances<'l>(&'l self) -> Result<HashMap<String, crate::Machine<'l>>, Error>;
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
