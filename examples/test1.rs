extern crate tsunami;

use std::collections::HashMap;
use std::time;
use tsunami::{Machine, MachineSetup, TsunamiBuilder};

fn main() {
    let mut b = TsunamiBuilder::default();
    b.use_term_logger();
    b.add_set(
        "server",
        1,
        MachineSetup::new("c5.xlarge", "ami-e18aa89b", |ssh| {
            ssh.cmd("cat /etc/hostname").map(|out| {
                println!("{}", out);
            })
        }),
    );
    b.add_set(
        "client",
        3,
        MachineSetup::new("c5.xlarge", "ami-e18aa89b", |ssh| {
            ssh.cmd("date").map(|out| {
                println!("{}", out);
            })
        }),
    );

    b.wait_limit(time::Duration::from_secs(10));
    b.run(|vms: HashMap<String, Vec<Machine>>| {
        println!("==> {}", vms["server"][0].private_ip);
        for c in &vms["client"] {
            println!(" -> {}", c.private_ip);
        }
        Ok(())
    }).unwrap();
}
