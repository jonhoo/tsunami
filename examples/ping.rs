use color_eyre::Report;
use rusoto_core::Region;
use tracing::instrument;
use tsunami::providers::aws;
use tsunami::{Machine, Tsunami};

#[instrument]
async fn ping(from: &Machine<'_>, to: &Machine<'_>) -> Result<(), Report> {
    let to_ip = &to.public_ip;

    let out = from
        .ssh
        .command("ping")
        .arg("-c")
        .arg("10")
        .arg(&to_ip)
        .output()
        .await?;
    let stdout = std::string::String::from_utf8(out.stdout)?;
    tracing::info!(ping = %stdout, "ping");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Report> {
    let ms = vec![
        (
            String::from("east"),
            aws::Setup::default()
                .region_with_ubuntu_ami(Region::UsEast1)
                .await?
                .setup(|vm| {
                    Box::pin(async move {
                        if let Err(e) = vm
                            .ssh
                            .command("sudo")
                            .arg("apt")
                            .arg("update")
                            .status()
                            .await
                        {
                            tracing::warn!("apt update failed: {}", e);
                        };

                        Ok(())
                    })
                }),
        ),
        (
            String::from("india"),
            aws::Setup::default()
                .region_with_ubuntu_ami(Region::ApSouth1)
                .await?
                .instance_type("t3.small")
                .setup(|vm| {
                    Box::pin(async move {
                        if let Err(e) = vm
                            .ssh
                            .command("sudo")
                            .arg("apt")
                            .arg("update")
                            .status()
                            .await
                        {
                            tracing::warn!("apt update failed: {}", e);
                        };

                        Ok(())
                    })
                }),
        ),
    ];

    let mut l: tsunami::providers::aws::Launcher<_> = Default::default();
    l.spawn(ms, Some(std::time::Duration::from_secs(30)))
        .await?;

    let vms = l.connect_all().await?;

    let east = vms.get("east").unwrap();
    let india = vms.get("india").unwrap();

    ping(east, india).await?;
    ping(india, east).await?;

    l.terminate_all().await?;
    Ok(())
}
