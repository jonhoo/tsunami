extern crate tsunami;

use rusoto_core::Region;
use std::collections::HashMap;
use std::time;
use tsunami::{Machine, MachineSetup, TsunamiBuilder};

fn main() -> Result<(), failure::Error> {
    let mut b = TsunamiBuilder::default();
    b.use_term_logger();

    let m = MachineSetup::default()
        .region(Region::UsEast1)
        .setup(|ssh| {
            ssh.cmd("sudo apt update").map(|(out, _)| {
                println!("{}", out);
            })
        });
    b.add("east".into(), m);

    let m = MachineSetup::default()
        .region(Region::ApSouth1)
        .instance_type("t3.small")
        .setup(|ssh| {
            ssh.cmd("sudo apt update").map(|(out, _)| {
                println!("{}", out);
            })
        });
    b.add("india".into(), m);

    b.wait_limit(time::Duration::from_secs(60));
    b.run(|vms: HashMap<String, Machine>| {
        for (name, vm) in vms {
            println!("{} ==> IP: {}", name, vm.public_ip);
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
