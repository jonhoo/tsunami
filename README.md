[![Build Status](https://travis-ci.org/jonhoo/tsunami.svg?branch=master)](https://travis-ci.org/jonhoo/tsunami)
![Maintenance](https://img.shields.io/badge/maintenance-passively--maintained-yellowgreen.svg)

# tsunami

`tsunami` provides an interface for running short-lived jobs and experiments on cloud
instances.

## Example

```rust
use tsunami::providers::{aws, azure, Launcher};
use rusoto_core::{credential::DefaultCredentialsProvider, Region as AWSRegion};
use azure::Region as AzureRegion;
#[tokio::main]
async fn main() -> Result<(), failure::Error> {
    // Initialize AWS
    let mut aws = aws::Launcher::default();
    // Create an AWS machine descriptor and add it to the AWS Tsunami
    aws.spawn(vec![(
        String::from("aws_vm"),
        aws::Setup::default()
            .region_with_ubuntu_ami(AWSRegion::UsWest1) // default is UsEast1
            .setup(|ssh, _| { // default is a no-op
                Box::pin(async move {
                    ssh.command("sudo").arg("apt").arg("update").status().await?;
                    ssh.command("bash").arg("-c")
                        .arg("\"curl https://sh.rustup.rs -sSf | sh -- -y\"").status().await?;
                    Ok(())
                })
            })
    )], None, None).await?;

    // Initialize Azure
    let mut azure = azure::Launcher::default();
    // Create an Azure machine descriptor and add it to the Azure Tsunami
    azure.spawn(vec![(
        String::from("azure_vm"),
        azure::Setup::default()
            .region(AzureRegion::FranceCentral) // default is EastUs
            .setup(|ssh, _| { // default is a no-op
                Box::pin(async move {
                    ssh.command("sudo").arg("apt").arg("update").status().await?;
                    ssh.command("bash").arg("-c")
                        .arg("\"curl https://sh.rustup.rs -sSf | sh -- -y\"").status().await?;
                    Ok(())
                })
            })
    )], None, None).await?;

    // SSH to the VM and run a command on it
    let aws_vms = aws.connect_all().await?;
    let azure_vms = azure.connect_all().await?;

    let vms = aws_vms.into_iter().chain(azure_vms.into_iter());

    // do things with my VMs!

    // call cleanup() to terminate the instances.
    aws.cleanup().await?;
    azure.cleanup().await?;
    Ok(())
}
```

## Live-coding

An earlier version of this crate was written as part of a live-coding stream series intended for users who
are already somewhat familiar with Rust, and who want to see something larger and more involved
be built. You can find the recordings of past sessions [on
YouTube](https://www.youtube.com/playlist?list=PLqbS7AVVErFgY2faCIYjJZv_RluGkTlKt).

License: MIT/Apache-2.0
