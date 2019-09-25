extern crate tsunami;

use rusoto_core::Region;
use slog::info;
use std::time;
use tsunami::providers::aws;
use tsunami::{Machine, TsunamiBuilder};

fn ping(from: &Machine, to: &Machine, log: &slog::Logger) -> Result<(), failure::Error> {
    let to_ip = &to.public_ip;

    let ssh = from.ssh.as_ref().unwrap();
    let (stdout, _) = ssh.cmd(&format!("ping -c 10 {}", &to_ip))?;
    info!(log, "ping"; "from" => &from.public_ip, "to" => to_ip, "ping" => stdout);
    Ok(())
}

fn main() -> Result<(), failure::Error> {
    let mut b = TsunamiBuilder::<aws::AWSRegion>::default();
    b.use_term_logger();

    let m = aws::MachineSetup::default()
        .region(Region::UsEast1)
        .setup(|ssh, _| ssh.cmd("sudo apt update").map(|(_, _)| ()));
    b.add("east".into(), m);

    let m = aws::MachineSetup::default()
        .region(Region::ApSouth1)
        .instance_type("t3.small")
        .setup(|ssh, _| ssh.cmd("sudo apt update").map(|(_, _)| ()));
    b.add("india".into(), m);

    b.wait_limit(time::Duration::from_secs(60));
    let ts = b.spawn()?;
    let vms = ts.get_machines()?;
    let log = ts.logger();

    let east = vms.get("east").unwrap();
    let india = vms.get("india").unwrap();

    ping(east, india, log)?;
    ping(india, east, log)?;

    Ok(())
}
