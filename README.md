# tsunami

[![Crates.io](https://img.shields.io/crates/v/tsunami.svg)](https://crates.io/crates/tsunami)
[![Documentation](https://docs.rs/tsunami/badge.svg)](https://docs.rs/tsunami/)
[![Build Status](https://travis-ci.org/jonhoo/tsunami.svg?branch=master)](https://travis-ci.org/jonhoo/tsunami)

`tsunami` provides an interface for running short-lived jobs and experiments on cloud
instances.

Most interaction with this library happens through
[`TsunamiBuilder`](struct.TsunamiBuilder.html) and [`Tsunami`](struct.Tsunami.html).

## Example

```rust
use tsunami::TsunamiBuilder;
use tsunami::providers::{Launcher, aws, azure};
use rusoto_core::{DefaultCredentialsProvider, Region as AWSRegion};
use azure::Region as AzureRegion;
fn main() -> Result<(), failure::Error> {
    // Initialize AWS
    let mut aws = aws::Launcher::default();

    // Initialize a TsunamiBuilder for AWS
    let mut tb_aws = TsunamiBuilder::default();
    tb_aws.use_term_logger();

    // Create an AWS machine descriptor and add it to the AWS Tsunami
    let m = aws::Setup::default()
        .region_with_ubuntu_ami(AWSRegion::UsWest1) // default is UsEast1
        .setup(|ssh, _| { // default is a no-op
            ssh.cmd("sudo apt update")?;
            ssh.cmd("curl https://sh.rustup.rs -sSf | sh -- -y")?;
            Ok(())
        });
    tb_aws.add("aws_vm", m);

    // Initialize Azure
    let mut azure = azure::Launcher::default();

    // Initialize a TsunamiBuilder for Azure
    let mut tb_azure = TsunamiBuilder::default();
    tb_azure.use_term_logger();

    // Create an Azure machine descriptor and add it to the Azure Tsunami
    let m = azure::Setup::default()
        .region(AzureRegion::FranceCentral) // default is EastUs
        .setup(|ssh, _| { // default is a no-op
            ssh.cmd("sudo apt update")?;
            ssh.cmd("curl https://sh.rustup.rs -sSf | sh -- -y")?;
            Ok(())
        });
    tb_azure.add("azure_vm", m);

    // Launch the VMs
    tb_aws.spawn(&mut aws)?;
    tb_azure.spawn(&mut azure)?;

    // SSH to the VM and run a command on it
    let aws_vms = aws.connect_all()?;
    let azure_vms = azure.connect_all()?;

    let vms = aws_vms.into_iter().chain(azure_vms.into_iter());

    // do things with my VMs!
    // VMs dropped when aws and azure are dropped.

    Ok(())
}
```

## Live-coding

An earlier version of this crate was written as part of a live-coding stream series intended for users who
are already somewhat familiar with Rust, and who want to see something larger and more involved
be built. You can find the recordings of past sessions [on
YouTube](https://www.youtube.com/playlist?list=PLqbS7AVVErFgY2faCIYjJZv_RluGkTlKt).
