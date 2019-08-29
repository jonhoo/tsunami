use rusoto_core::Region;
use structopt::StructOpt;
use tsunami::providers::{aws::MachineSetup, Setup};
use tsunami::TsunamiBuilder;

#[derive(StructOpt)]
struct Opt {
    #[structopt(short = "r", long = "region")]
    region: Region,
}

// just launch an instance in the specified region and wait.
fn main() {
    let opt = Opt::from_args();

    let mut b = TsunamiBuilder::default();
    b.use_term_logger();

    let m = MachineSetup::default()
        .region(opt.region)
        .instance_type("t3.medium");

    b.add(String::from("machine"), Setup::AWS(m));
    b.run(true, |_, _| {
        println!("launched");
        Ok(())
    })
    .unwrap();
}
