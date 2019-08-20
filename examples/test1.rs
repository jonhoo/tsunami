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
            ssh.cmd("sudo apt update").map(|out| {
                println!("{}", out);
            })
        });
    b.add(m);

    let m = MachineSetup::default()
        .region(Region::ApSouth1)
        .instance_type("t3.small")
        .setup(|ssh| {
            ssh.cmd("sudo apt update").map(|out| {
                println!("{}", out);
            })
        });
    b.add(m);

    b.wait_limit(time::Duration::from_secs(30));
    b.run(|vms: HashMap<String, Machine>| {
        for vm in vms.values() {
            println!("==> IP: {}", vm.public_ip);
        }

        for vm in vms.values() {
            vm.ssh.as_ref().map(|ssh| {
                ssh.cmd("ip addr && hostname && sleep 300").map(|out| {
                    println!("{}", out);
                })
            });
        }

        Ok(())
    })?;

    Ok(())
}
