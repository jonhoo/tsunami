use failure::bail;
use rusoto_core::DefaultCredentialsProvider;
use structopt::StructOpt;
use tsunami::providers::Launcher;
use tsunami::TsunamiBuilder;

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

fn launch_and_wait<L: Launcher>(mut b: TsunamiBuilder<L>, l: &mut L) -> Result<(), failure::Error> {
    let log = b.logger();
    b.spawn(l)?;
    wait_for_continue(&log);
    Ok(())
}

// just launch an instance in the specified region and wait.
fn main() -> Result<(), failure::Error> {
    let opt = Opt::from_args();

    match opt.provider {
        Providers::AWS => {
            let mut b = TsunamiBuilder::default();
            b.use_term_logger();
            let m = tsunami::providers::aws::MachineSetup::default()
                .region(opt.region.parse()?)
                .instance_type("t3.medium");

            b.add("machine", m).unwrap();
            let mut l: tsunami::providers::aws::AWSLauncher<_> = Default::default();
            l.with_credentials(|| Ok(DefaultCredentialsProvider::new()?));
            launch_and_wait::<tsunami::providers::aws::AWSLauncher<_>>(b, &mut l)?;
        }
        Providers::Azure => {
            let mut b = TsunamiBuilder::default();
            b.use_term_logger();
            let m = tsunami::providers::azure::Setup::default().region(opt.region.parse()?);

            b.add("machine", m).unwrap();
            let mut l = Default::default();
            launch_and_wait::<tsunami::providers::azure::AzureLauncher>(b, &mut l)?;
        }
    }

    Ok(())
}
