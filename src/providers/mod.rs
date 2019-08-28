use failure::Error;
use rusoto_core::DefaultCredentialsProvider;
use std::collections::HashMap;

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

pub mod aws;
use aws::AWSRegion;

pub mod baremetal;
use baremetal::Machine;

pub enum Provider {
    AWS(AWSRegion),
    Bare(Machine),
}

unsafe impl Send for Provider {}

impl Launcher for Provider {
    type Region = String;
    type Machine = Setup;

    fn region(&self) -> Self::Region {
        match self {
            Provider::AWS(x) => x.region(),
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
    Bare(baremetal::Setup),
}

unsafe impl Send for Setup {}

impl MachineSetup for Setup {
    type Region = String;
    fn region(&self) -> Self::Region {
        match self {
            Setup::AWS(x) => format!("aws:{}", x.region()),
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
            Setup::Bare(_) => Ok(Provider::Bare(Machine { log })),
        }
    }
}
