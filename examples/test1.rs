extern crate tsunami;

use rusoto_core::Region;
use slog::info;
use std::collections::HashMap;
use std::time;
use tsunami::providers::{aws::MachineSetup, Setup};
use tsunami::{Machine, TsunamiBuilder};

fn main() -> Result<(), failure::Error> {
    let mut b = TsunamiBuilder::default();
    b.use_term_logger();

    let m = MachineSetup::default()
        .region(Region::UsEast1)
        .setup(|ssh, _| ssh.cmd("sudo apt update").map(|(_, _)| ()));
    b.add("east".into(), Setup::AWS(m));

    let m = MachineSetup::default()
        .region(Region::ApSouth1)
        .instance_type("t3.small")
        .setup(|ssh, _| ssh.cmd("sudo apt update").map(|(_, _)| ()));
    b.add("india".into(), Setup::AWS(m));

    b.wait_limit(time::Duration::from_secs(60));
    b.run(false, |vms: HashMap<String, Machine>, log| {
        for (name, vm) in vms {
            info!(log, "doing stuff on machine"; "name" => name, "ip" => vm.public_ip);
            vm.ssh.as_ref().map(|ssh| {
                ssh.cmd("ip addr").map(|(out, _)| {
                    println!("{}", out);
                })
            });
        }

        Ok(())
    })?;

    Ok(())
}
