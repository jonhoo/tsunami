use failure::Error;
use rusoto_core::DefaultCredentialsProvider;
use std::collections::HashMap;

/// This is used to group machines into connections
/// to cloud providers. e.g., for AWS we need a separate
/// connection to each region.
pub trait MachineSetup {
    type Region: Eq + std::hash::Hash;
    fn region(&self) -> Self::Region;
}

pub trait Launcher {
    type Region: Eq + std::hash::Hash;
    type Machine: MachineSetup<Region = Self::Region>;

    fn region(&self) -> Self::Region;
    fn init_instances(
        &mut self,
        max_instance_duration: Option<std::time::Duration>,
        max_wait: Option<std::time::Duration>,
        machines: impl IntoIterator<Item = (String, Self::Machine)>,
    ) -> Result<HashMap<String, crate::Machine>, Error>;
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
use aws::AWSRegion;

pub mod baremetal;
use baremetal::Machine;

pub mod azure;

pub enum Provider {
    AWS(AWSRegion),
    Azure(azure::AzureRegion),
    Bare(Machine),
}

impl Launcher for Provider {
    type Region = String;
    type Machine = Setup;

    fn region(&self) -> Self::Region {
        match self {
            Provider::AWS(x) => x.region(),
            Provider::Azure(x) => format!("az:{}", x.region().to_string()),
            Provider::Bare(x) => x.region(),
        }
    }

    fn init_instances(
        &mut self,
        max_instance_duration: Option<std::time::Duration>,
        max_wait: Option<std::time::Duration>,
        machines: impl IntoIterator<Item = (String, Self::Machine)>,
    ) -> Result<HashMap<String, crate::Machine>, Error> {
        match self {
            Provider::AWS(x) => {
                let ms = machines.into_iter().map(|(s, m)| match m {
                    Setup::AWS(a) => (s, a),
                    _ => unreachable!(),
                });
                x.init_instances(max_instance_duration, max_wait, ms)
            }
            Provider::Azure(x) => {
                let ms = machines.into_iter().map(|(s, m)| match m {
                    Setup::Azure(a) => (s, a),
                    _ => unreachable!(),
                });
                x.init_instances(max_instance_duration, max_wait, ms)
            }
            Provider::Bare(x) => {
                let ms = machines.into_iter().map(|(s, m)| match m {
                    Setup::Bare(a) => (s, a),
                    _ => unreachable!(),
                });
                x.init_instances(max_instance_duration, max_wait, ms)
            }
        }
    }
}

pub enum Setup {
    AWS(aws::MachineSetup),
    Azure(azure::Setup),
    Bare(baremetal::Setup),
}

impl MachineSetup for Setup {
    type Region = String;
    fn region(&self) -> Self::Region {
        match self {
            Setup::AWS(x) => format!("aws:{}", x.region()),
            Setup::Azure(x) => format!("az:{}", x.region().to_string()),
            Setup::Bare(x) => x.region(),
        }
    }
}

impl Setup {
    pub fn init_provider(&self, log: slog::Logger) -> Result<Provider, Error> {
        match self {
            Setup::AWS(x) => {
                let provider = DefaultCredentialsProvider::new()?;
                let ec2 = AWSRegion::new(&x.region(), provider, log)?;
                Ok(Provider::AWS(ec2))
            }
            Setup::Azure(x) => {
                let az = azure::AzureRegion::new(&x.region().to_string(), log)?;
                Ok(Provider::Azure(az))
            }
            Setup::Bare(_) => Ok(Provider::Bare(Machine { log })),
        }
    }
}
