use color_eyre::Report;
use structopt::StructOpt;
use tracing::instrument;
use tsunami::providers::Launcher;

#[derive(Debug)]
enum Providers {
    AWS,
    Azure,
}

impl std::str::FromStr for Providers {
    type Err = Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "aws" => Providers::AWS,
            "azure" => Providers::Azure,
            x => eyre::bail!("unknown provider {:?}", x),
        })
    }
}

#[derive(StructOpt)]
struct Opt {
    #[structopt(short = "p", long = "provider")]
    provider: Providers,
    #[structopt(short = "r", long = "region")]
    region: String,
}

fn wait_for_continue() {
    eprintln!("pausing for manual instance inspection, press enter to continue");

    use std::io::prelude::*;
    let stdin = std::io::stdin();
    let mut iterator = stdin.lock().lines();
    iterator.next().unwrap().unwrap();
}

// just launch an instance in the specified region and wait.
#[tokio::main]
async fn main() -> Result<(), Report> {
    let opt = Opt::from_args();

    match opt.provider {
        Providers::AWS => {
            let mut l: tsunami::providers::aws::Launcher<_> = Default::default();
            l.open_ports();
            let m = tsunami::providers::aws::Setup::default()
                .region_with_ubuntu_ami(opt.region.parse()?)
                .await?
                .instance_type("t3.medium");

            l.spawn(vec![(String::from(""), m)], None).await?;
            wait_for_continue();
            l.terminate_all().await?;
        }
        Providers::Azure => {
            let mut l: tsunami::providers::azure::Launcher = Default::default();
            let m = tsunami::providers::azure::Setup::default().region(opt.region.parse()?);

            l.spawn(vec![(String::from(""), m)], None).await?;
            wait_for_continue();
            l.terminate_all().await?;
        }
    }

    Ok(())
}
