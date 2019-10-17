extern crate tsunami;

use rusoto_core::DefaultCredentialsProvider;
use rusoto_core::Region;
use slog::info;
use tsunami::providers::{aws, Launcher};
use tsunami::{Machine, TsunamiBuilder};

fn ping(from: &Machine, to: &Machine, log: &slog::Logger) -> Result<(), failure::Error> {
    let to_ip = &to.public_ip;

    let ssh = from.ssh.as_ref().unwrap();
    let (stdout, _) = ssh.cmd(&format!("ping -c 10 {}", &to_ip))?;
    info!(log, "ping"; "from" => &from.public_ip, "to" => to_ip, "ping" => stdout);
    Ok(())
}

fn main() -> Result<(), failure::Error> {
    let mut b = TsunamiBuilder::default();
    b.use_term_logger()
        .timeout(std::time::Duration::from_secs(30));

    let m = aws::MachineSetup::default()
        .region_with_ubuntu_ami(Region::UsEast1)
        .setup(|ssh, _| ssh.cmd("sudo apt update").map(|(_, _)| ()));
    b.add("east", m).unwrap();

    let m = aws::MachineSetup::default()
        .region_with_ubuntu_ami(Region::ApSouth1)
        .instance_type("t3.small")
        .setup(|ssh, _| ssh.cmd("sudo apt update").map(|(_, _)| ()));
    b.add("india", m).unwrap();

    let mut l: tsunami::providers::aws::AWSLauncher<_> = Default::default();
    l.with_credentials(|| Ok(DefaultCredentialsProvider::new()?));

    let log = b.logger();
    b.spawn(&mut l)?;
    let vms = l.connect_all()?;

    let east = vms.get("east").unwrap();
    let india = vms.get("india").unwrap();

    ping(east, india, &log)?;
    ping(india, east, &log)?;

    Ok(())
}
