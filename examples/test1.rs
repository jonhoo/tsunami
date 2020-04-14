extern crate tsunami;

use rusoto_core::Region;
use slog::{info, warn};
use tsunami::providers::{aws, Launcher};
use tsunami::{Machine, TsunamiBuilder};

fn ping(from: &Machine, to: &Machine, log: &slog::Logger) -> Result<(), failure::Error> {
    let to_ip = &to.public_ip;

    let ssh = from.ssh.as_ref().unwrap();
    let out = ssh
        .command("ping")
        .arg("-c")
        .arg("10")
        .arg(&to_ip)
        .output()?;
    let stdout = std::string::String::from_utf8(out.stdout)?;
    info!(log, "ping"; "from" => &from.public_ip, "to" => to_ip, "ping" => stdout);
    Ok(())
}

fn main() -> Result<(), failure::Error> {
    let mut b = TsunamiBuilder::default();
    b.use_term_logger()
        .timeout(std::time::Duration::from_secs(30));

    let m = aws::Setup::default()
        .region_with_ubuntu_ami(Region::UsEast1)
        .setup(|ssh, log| {
            if let Err(e) = ssh.command("sudo").arg("apt").arg("update").status() {
                warn!(&log, "apt update failed"; "err" => ?e);
            };

            Ok(())
        });
    b.add("east", m).unwrap();

    let m = aws::Setup::default()
        .region_with_ubuntu_ami(Region::ApSouth1)
        .instance_type("t3.small")
        .setup(|ssh, log| {
            if let Err(e) = ssh.command("sudo").arg("apt").arg("update").status() {
                warn!(&log, "apt update failed"; "err" => ?e);
            };

            Ok(())
        });
    b.add("india", m).unwrap();

    let mut l: tsunami::providers::aws::Launcher<_> = Default::default();

    let log = b.logger();
    b.spawn(&mut l)?;
    let vms = l.connect_all()?;

    let east = vms.get("east").unwrap();
    let india = vms.get("india").unwrap();

    ping(east, india, &log)?;
    ping(india, east, &log)?;

    Ok(())
}
