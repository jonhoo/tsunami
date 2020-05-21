# tsunami

**Note that the new async version + Azure support is not yet on crates.io. It'll come soon!**

[![Crates.io](https://img.shields.io/crates/v/tsunami.svg)](https://crates.io/crates/tsunami)
[![Documentation](https://docs.rs/tsunami/badge.svg)](https://docs.rs/tsunami/)
[![Build Status](https://travis-ci.org/jonhoo/tsunami.svg?branch=master)](https://travis-ci.org/jonhoo/tsunami)

`tsunami` provides an interface for running one-off jobs on cloud instances.

Imagine you need to run an experiment that involves four machines of different types on AWS. Or
on Azure. And each one needs to be set up in a particular way. Maybe one is a server, two are
load generating clients, and one is a monitor of some sort. You want to spin them all up with a
custom AMI, in different regions, and then run some benchmarks once they're all up and running.

This crate makes that trivial.

You say what machines you want, and the library takes care of the rest. It uses the cloud
service's API to start the machines as appropriate, and gives you [ssh connections] to each
host as it becomes available to run setup. When all the machines are available, you can connect
to them all in a single step, and then run your distributed job. When you're done, `tsunami`
tears everything down for you. And did I mention it even supports AWS spot instances, so it
even saves you money?

How does this magic work? Take a look at this example:

```rust
use azure::Region as AzureRegion;
use rusoto_core::{credential::DefaultCredentialsProvider, Region as AWSRegion};
use tsunami::Tsunami;
use tsunami::providers::{aws, azure};
#[tokio::main]
async fn main() -> Result<(), color_eyre::Report> {
    // Initialize AWS
    let mut aws = aws::Launcher::default();
    // Create an AWS machine descriptor and add it to the AWS Tsunami
    aws.spawn(
        vec![(
            String::from("aws_vm"),
            aws::Setup::default()
                .region_with_ubuntu_ami(AWSRegion::UsWest1) // default is UsEast1
                .await
                .unwrap()
                .setup(|ssh| {
                    // default is a no-op
                    Box::pin(async move {
                        ssh.command("sudo")
                            .arg("apt")
                            .arg("update")
                            .status()
                            .await?;
                        ssh.command("bash")
                            .arg("-c")
                            .arg("\"curl https://sh.rustup.rs -sSf | sh -- -y\"")
                            .status()
                            .await?;
                        Ok(())
                    })
                }),
        )],
        None,
    )
    .await?;

    // Initialize Azure
    let mut azure = azure::Launcher::default();
    // Create an Azure machine descriptor and add it to the Azure Tsunami
    azure
        .spawn(
            vec![(
                String::from("azure_vm"),
                azure::Setup::default()
                    .region(AzureRegion::FranceCentral) // default is EastUs
                    .setup(|ssh| {
                        // default is a no-op
                        Box::pin(async move {
                            ssh.command("sudo")
                                .arg("apt")
                                .arg("update")
                                .status()
                                .await?;
                            ssh.command("bash")
                                .arg("-c")
                                .arg("\"curl https://sh.rustup.rs -sSf | sh -- -y\"")
                                .status()
                                .await?;
                            Ok(())
                        })
                    }),
            )],
            None,
        )
        .await?;

    // SSH to the VMs and run commands on it
    let aws_vms = aws.connect_all().await?;
    let azure_vms = azure.connect_all().await?;

    let vms = aws_vms.into_iter().chain(azure_vms.into_iter());

    // do amazing things with the VMs!
    // you have access to things like ip addresses for each host too.

    // call terminate_all() to terminate the instances.
    aws.terminate_all().await?;
    azure.terminate_all().await?;
    Ok(())
}
```

## Live-coding

An earlier version of this crate was written as part of a live-coding stream series intended
for users who are already somewhat familiar with Rust, and who want to see something larger and
more involved be built. You can find the recordings of past sessions [on
YouTube](https://www.youtube.com/playlist?list=PLqbS7AVVErFgY2faCIYjJZv_RluGkTlKt).
