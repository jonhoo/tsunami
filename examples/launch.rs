use failure::bail;
use structopt::StructOpt;
use tsunami::providers::Launcher;

#[derive(Debug)]
enum Providers {
    AWS,
    Azure,
}

impl std::str::FromStr for Providers {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "aws" => Providers::AWS,
            "azure" => Providers::Azure,
            x => bail!("unknown provider {:?}", x),
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

fn wait_for_continue(log: &slog::Logger) {
    slog::debug!(
        log,
        "pausing for manual instance inspection, press enter to continue"
    );

    use std::io::prelude::*;
    let stdin = std::io::stdin();
    let mut iterator = stdin.lock().lines();
    iterator.next().unwrap().unwrap();
}

// just launch an instance in the specified region and wait.
#[tokio::main]
async fn main() -> Result<(), failure::Error> {
    let opt = Opt::from_args();

    match opt.provider {
        Providers::AWS => {
            let log = tsunami::get_term_logger();
            let mut l: tsunami::providers::aws::Launcher<_> = Default::default();
            l.open_ports();
            let m = tsunami::providers::aws::Setup::default()
                .region_with_ubuntu_ami(opt.region.parse()?)
                .instance_type("t3.medium");

            l.spawn(vec![(String::from(""), m)], None, Some(log.clone()))
                .await?;
            wait_for_continue(&log);
            l.cleanup().await?;
        }
        Providers::Azure => {
            let log = tsunami::get_term_logger();
            let mut l: tsunami::providers::azure::Launcher = Default::default();
            let m = tsunami::providers::azure::Setup::default().region(opt.region.parse()?);

            l.spawn(vec![(String::from(""), m)], None, Some(log.clone()))
                .await?;
            wait_for_continue(&log);
            l.cleanup().await?;
        }
    }

    Ok(())
}
