extern crate tsunami;

use rusoto_core::Region;
use slog::{info, warn};
use tsunami::providers::{aws, Launcher};
use tsunami::Machine;

async fn ping(
    from: &Machine<'_>,
    to: &Machine<'_>,
    log: &slog::Logger,
) -> Result<(), failure::Error> {
    let to_ip = &to.public_ip;

    let ssh = from.ssh.as_ref().unwrap();
    let out = ssh
        .command("ping")
        .arg("-c")
        .arg("10")
        .arg(&to_ip)
        .output()
        .await?;
    let stdout = std::string::String::from_utf8(out.stdout)?;
    info!(log, "ping"; "from" => &from.public_ip, "to" => to_ip, "ping" => stdout);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), failure::Error> {
    let ms = vec![
        (
            String::from("east"),
            aws::Setup::default()
                .region_with_ubuntu_ami(Region::UsEast1)
                .setup(|ssh, log| {
                    Box::pin(async move {
                        if let Err(e) = ssh.command("sudo").arg("apt").arg("update").status().await
                        {
                            warn!(&log, "apt update failed"; "err" => ?e);
                        };

                        Ok(())
                    })
                }),
        ),
        (
            String::from("india"),
            aws::Setup::default()
                .region_with_ubuntu_ami(Region::ApSouth1)
                .instance_type("t3.small")
                .setup(|ssh, log| {
                    Box::pin(async move {
                        if let Err(e) = ssh.command("sudo").arg("apt").arg("update").status().await
                        {
                            warn!(&log, "apt update failed"; "err" => ?e);
                        };

                        Ok(())
                    })
                }),
        ),
    ];

    let log = tsunami::get_term_logger();
    let mut l: tsunami::providers::aws::Launcher<_> = Default::default();
    l.spawn(
        ms,
        Some(std::time::Duration::from_secs(30)),
        Some(log.clone()),
    )
    .await?;

    let vms = l.connect_all().await?;

    let east = vms.get("east").unwrap();
    let india = vms.get("india").unwrap();

    ping(east, india, &log).await?;
    ping(india, east, &log).await?;

    Ok(())
}
