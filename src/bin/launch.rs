use failure::bail;
use structopt::StructOpt;
use tsunami::providers::Setup;
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

// just launch an instance in the specified region and wait.
fn main() -> Result<(), failure::Error> {
    let opt = Opt::from_args();

    let mut b = TsunamiBuilder::default();
    b.use_term_logger();

    match opt.provider {
        Providers::AWS => {
            let m = tsunami::providers::aws::MachineSetup::default()
                .region(opt.region.parse()?)
                .instance_type("t3.medium");

            b.add(String::from("machine"), Setup::AWS(m));
        }
        Providers::Azure => {
            let m = tsunami::providers::azure::Setup::default().region(opt.region.parse()?);

            b.add(String::from("machine"), Setup::Azure(m));
        }
    }

    b.run(true, |_, _| {
        println!("launched");
        Ok(())
    })
    .unwrap();

    Ok(())
}
