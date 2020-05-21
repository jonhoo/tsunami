//! Azure backend for tsunami.
//!
//! The primary `impl Launcher` type is [`Launcher`].
//! It internally uses the lower-level, region-specific [`azure::RegionLauncher`].
//! Both these types use [`azure::Setup`] as their descriptor type.
//!
//! Azure does not support Spot or Defined Duration instances.
//! As a result, *if your tsunami crashes or you forget to call `terminate_all()`, you must manually terminate your instances to avoid extra costs*.
//! The easiest way to do this is to delete resource groups beginning with `tsunami_`:
//! `az group delete --name <name> --yes`.
//! You can find such resource groups using:
//! `az group list`.
//!
//! To use this provider, you must [install the Azure
//! CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest),
//! and the `az` command must be in your `$PATH`.
//! Also, you must run `az login` to authenticate with Microsoft.
//!
//! # Example
//! ```rust,no_run
//! use tsunami::Tsunami;
//! use tsunami::providers::azure;
//! #[tokio::main]
//! async fn main() {
//!     let mut l = azure::Launcher::default();
//!     l.spawn(vec![(String::from("my machine"), azure::Setup::default())], None).await.unwrap();
//!     let vms = l.connect_all().await.unwrap();
//!     let my_machine = vms.get("my machine").unwrap();
//!     let out = my_machine
//!         .ssh
//!         .command("echo")
//!         .arg("\"Hello, Azure\"")
//!         .output()
//!         .await
//!         .unwrap();
//!     let stdout = std::string::String::from_utf8(out.stdout).unwrap();
//!     println!("{}", stdout);
//!     l.terminate_all().await.unwrap();
//! }
//! ```
//! ```rust,no_run
//! use tsunami::providers::azure;
//! use tsunami::Tsunami;
//! #[tokio::main]
//! async fn main() -> Result<(), color_eyre::Report> {
//!     // Initialize Azure
//!     let mut azure = azure::Launcher::default();
//!
//!     // Create a machine descriptor and add it to the Tsunami
//!     let m = azure::Setup::default()
//!         .region(azure::Region::FranceCentral) // default is EastUs
//!         .setup(|ssh| {
//!             // default is a no-op
//!             Box::pin(async move {
//!                 ssh.command("sudo")
//!                     .arg("apt")
//!                     .arg("update")
//!                     .status()
//!                     .await?;
//!                 ssh.command("bash")
//!                     .arg("-c")
//!                     .arg("\"curl https://sh.rustup.rs -sSf | sh -- -y\"")
//!                     .status()
//!                     .await?;
//!                 Ok(())
//!             })
//!         });
//!
//!     // Launch the VM
//!     azure.spawn(vec![(String::from("my_vm"), m)], None).await?;
//!
//!     // SSH to the VM and run a command on it
//!     let vms = azure.connect_all().await?;
//!     let my_vm = vms.get("my_vm").unwrap();
//!     println!("public ip: {}", my_vm.public_ip);
//!     my_vm.ssh
//!         .command("git")
//!         .arg("clone")
//!         .arg("https://github.com/jonhoo/tsunami")
//!         .status()
//!         .await?;
//!     my_vm.ssh
//!         .command("bash")
//!         .arg("-c")
//!         .arg("\"cd tsunami && cargo build\"")
//!         .status()
//!         .await?;
//!     azure.terminate_all().await?;
//!     Ok(())
//! }
//! ```

use crate::ssh;
use color_eyre::{Help, Report};
use educe::Educe;
use eyre::{eyre, WrapErr};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tracing::instrument;
use tracing_futures::Instrument;

/// A descriptor for a single Azure VM type.
///
/// The default is an UbuntuLTS, Standard_DS1_V2 VM in the East US region.
#[derive(Clone, Educe)]
#[educe(Debug)]
pub struct Setup {
    region: Region,
    instance_type: String,
    image: String,
    username: String,
    #[educe(Debug(ignore))]
    setup_fn: Option<
        Arc<
            dyn for<'r> Fn(
                    &'r mut ssh::Session,
                )
                    -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'r>>
                + Send
                + Sync
                + 'static,
        >,
    >,
}

impl Default for Setup {
    fn default() -> Self {
        Setup {
            region: "eastus".parse().unwrap(),
            instance_type: "Standard_B1s".to_string(),
            image: "UbuntuLTS".to_string(),
            username: "ubuntu".to_string(),
            setup_fn: None,
        }
    }
}

impl super::MachineSetup for Setup {
    type Region = Region;

    fn region(&self) -> Self::Region {
        self.region
    }
}

impl Setup {
    /// See also [`Region`].
    pub fn region(mut self, r: Region) -> Self {
        self.region = r;
        self
    }

    /// To view the available sizes in the relevant region, use:
    /// ```bash
    /// az vm list-sizes -l <region_name>
    /// ```
    ///
    /// The default is "Standard_DS1_v2".
    pub fn instance_type(mut self, inst_type: String) -> Self {
        self.instance_type = inst_type;
        self
    }

    /// Set the image.
    ///
    /// ```bash
    /// az vm image list
    /// ```
    /// shows the valid options.
    pub fn image(mut self, image: String) -> Self {
        self.image = image;
        self
    }

    /// Set the username.
    pub fn username(mut self, username: String) -> Self {
        self.username = username;
        self
    }

    /// The provided callback, `setup`, is called once for every spawned instances of this type with a handle
    /// to the target machine. Use [`crate::Machine::ssh`] to issue
    /// commands on the host in question.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tsunami::providers::azure::Setup;
    ///
    /// let m = Setup::default().setup(|ssh| {
    ///     Box::pin(async move {
    ///         ssh.command("sudo")
    ///             .arg("apt")
    ///             .arg("update")
    ///             .status()
    ///             .await?;
    ///         Ok(())
    ///     })
    /// });
    /// ```
    pub fn setup(
        mut self,
        setup: impl for<'r> Fn(
                &'r mut ssh::Session,
            ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'r>>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.setup_fn = Some(Arc::new(setup));
        self
    }
}

/// Launcher type for the Microsoft Azure cloud.
///
/// This is a lower-level API. Most users will use [`crate::TsunamiBuilder::spawn`].
///
/// This implementation relies on the [Azure
/// CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest).
/// It also assumes you have previously run `az login` to authenticate.
/// The Azure CLI will generate `~/.ssh/id_rsa.pub` if it does not exist, and use it to
/// authenticate to the machine. This file won't automatically be deleted if Azure created it.
///
/// While the regions are initialized serially, the setup functions for each machine are executed
/// in parallel (within each region).
#[derive(Debug, Default)]
pub struct Launcher {
    regions: HashMap<Region, RegionLauncher>,
}

impl super::Launcher for Launcher {
    type MachineDescriptor = Setup;

    #[instrument(level = "debug", skip(self))]
    fn launch<'l>(
        &'l mut self,
        l: super::LaunchDescriptor<Self::MachineDescriptor>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'l>> {
        Box::pin(
            async move {
                azcmd::check_az().await?;

                use std::collections::hash_map::Entry;
                let mut region = self.regions.entry(l.region);
                let region = match region {
                    Entry::Occupied(ref mut o) => o.get_mut(),
                    Entry::Vacant(v) => {
                        let region_span = tracing::debug_span!("new_region", region = %l.region);
                        let az_region = RegionLauncher::new(l.region)
                            .instrument(region_span)
                            .await?;
                        v.insert(az_region)
                    }
                };

                let region_span = tracing::debug_span!("region", region = %l.region);
                region.launch(l).instrument(region_span).await?;
                Ok(())
            }
            .in_current_span(),
        )
    }

    #[instrument(level = "debug")]
    fn connect_all<'l>(
        &'l self,
    ) -> Pin<
        Box<dyn Future<Output = Result<HashMap<String, crate::Machine<'l>>, Report>> + Send + 'l>,
    > {
        Box::pin(async move { collect!(self.regions) }.in_current_span())
    }

    #[instrument(level = "debug")]
    fn terminate_all(self) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send>> {
        Box::pin(
            async move {
                for (region, r) in self.regions {
                    let region_span = tracing::debug_span!("region", %region);
                    r.terminate_all().instrument(region_span).await?;
                }

                Ok(())
            }
            .in_current_span(),
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct IpInfo {
    public_ip: String,
    private_ip: String,
}

#[derive(Debug, Clone)]
struct Descriptor {
    name: String,
    username: String,
    ip: IpInfo,
}

/// Region-specific connection to Azure.
///
/// Each instance of this type creates one Azure
/// "resource group" and deletes the group on `terminate_all()`. See also [`Launcher`].
///
/// This implementation relies on the [Azure
/// CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest).
/// It also assumes you have previously run `az login` to authenticate with Microsoft.
/// The Azure CLI will generate `~/.ssh/id_rsa.pub` if it does not exist, and use it to
/// authenticate to the machine. This file won't automatically be deleted if Azure created it.
#[derive(Debug, Default)]
pub struct RegionLauncher {
    /// The region this [`RegionLauncher`] is connected to.
    pub region: Region,
    resource_group_name: String,
    machines: Vec<Descriptor>,
}

impl RegionLauncher {
    /// Create a new instance of RegionLauncher.
    pub async fn new(region: Region) -> Result<Self, Report> {
        let rg_name = super::rand_name("resourcegroup");

        azcmd::create_resource_group(region, &rg_name).await?;

        Ok(Self {
            region,
            resource_group_name: rg_name,
            machines: vec![],
        })
    }
}

impl super::Launcher for RegionLauncher {
    type MachineDescriptor = Setup;

    #[instrument(level = "debug", skip(self))]
    fn launch<'l>(
        &'l mut self,
        l: super::LaunchDescriptor<Self::MachineDescriptor>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'l>> {
        Box::pin(
            async move {
                let max_wait = l.max_wait;
                self.machines = futures_util::future::join_all(l.machines.into_iter().map(
                    |(nickname, desc)| {
                        let machine_span = tracing::debug_span!("machine", %nickname, ?desc);
                        async {
                            let vm_name = super::rand_name_sep("vm", "-");
                            tracing::debug!(%vm_name, "setting up instance");

                            let ipinfo = azcmd::create_vm(
                                &self.resource_group_name,
                                &vm_name,
                                &desc.instance_type,
                                &desc.image,
                                &desc.username,
                            )
                            .await?;
                            azcmd::open_ports(&self.resource_group_name, &vm_name).await?;

                            if let Setup {
                                ref username,
                                setup_fn: Some(ref f),
                                ..
                            } = desc
                            {
                                super::setup_machine(
                                    &nickname,
                                    &ipinfo.public_ip,
                                    &username,
                                    max_wait,
                                    None,
                                    f.as_ref(),
                                )
                                .await?;
                            }

                            Ok::<_, Report>(Descriptor {
                                name: nickname,
                                username: desc.username,
                                ip: ipinfo,
                            })
                        }
                        .instrument(machine_span)
                    },
                ))
                .await
                .into_iter()
                .collect::<Result<Vec<_>, Report>>()?;

                Ok(())
            }
            .in_current_span(),
        )
    }

    #[instrument(level = "debug")]
    fn connect_all<'l>(
        &'l self,
    ) -> Pin<
        Box<dyn Future<Output = Result<HashMap<String, crate::Machine<'l>>, Report>> + Send + 'l>,
    > {
        Box::pin(
            async move {
                futures_util::future::join_all(self.machines.iter().map(|desc| {
                    let machine_span = tracing::debug_span!("machine", name = %desc.name, ?desc);

                    let Descriptor {
                        name,
                        username,
                        ip:
                            IpInfo {
                                public_ip,
                                private_ip,
                            },
                    } = desc;
                    let m = crate::MachineDescriptor {
                        nickname: name.clone(),
                        public_dns: public_ip.clone(),
                        public_ip: public_ip.clone(),
                        private_ip: Some(private_ip.clone()),
                        _tsunami: Default::default(),
                    };

                    async move {
                        let m = m.connect_ssh(username, None, None, 22).await?;
                        Ok::<_, Report>((name.clone(), m))
                    }
                    .instrument(machine_span)
                }))
                .await
                .into_iter()
                .collect::<Result<HashMap<_, _>, Report>>()
            }
            .in_current_span(),
        )
    }

    #[instrument(level = "debug")]
    fn terminate_all(self) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send>> {
        let name = self.resource_group_name;
        Box::pin(
            async move {
                azcmd::delete_resource_group(&name).await?;
                Ok(())
            }
            .in_current_span(),
        )
    }
}

/// Available regions to launch VMs in.
///
/// See https://azure.microsoft.com/en-us/global-infrastructure/locations/ for more information.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Region {
    EastUs,
    EastUs2,
    WestUs,
    CentralUs,
    NorthCentralUs,
    SouthCentralUs,
    NorthEurope,
    WestEurope,
    EastUsia,
    SouthEastAsia,
    JapanEast,
    JapanWest,
    AustraliaEast,
    AustraliaSoutheast,
    AustraliaCentral,
    BrazilSouth,
    SouthIndia,
    CentralIndia,
    WestIndia,
    CanadaCentral,
    CanadaEast,
    WestUs2,
    WestCentralus,
    UkSouth,
    UkWest,
    KoreaCentral,
    KoreaSouth,
    FranceCentral,
    SouthAfricaNorth,
    UaeNorth,
    GermanyWestCentral,
}

impl Default for Region {
    fn default() -> Self {
        Region::EastUs
    }
}

impl AsRef<str> for Region {
    fn as_ref(&self) -> &str {
        match self {
            Region::EastUs => "eastus",
            Region::EastUs2 => "eastus2",
            Region::WestUs => "westus",
            Region::CentralUs => "centralus",
            Region::NorthCentralUs => "northcentralus",
            Region::SouthCentralUs => "southcentralus",
            Region::NorthEurope => "northeurope",
            Region::WestEurope => "westeurope",
            Region::EastUsia => "eastasia",
            Region::SouthEastAsia => "southeastasia",
            Region::JapanEast => "japaneast",
            Region::JapanWest => "japanwest",
            Region::AustraliaEast => "australiaeast",
            Region::AustraliaSoutheast => "australiasoutheast",
            Region::AustraliaCentral => "australiacentral",
            Region::BrazilSouth => "brazilsouth",
            Region::SouthIndia => "southindia",
            Region::CentralIndia => "centralindia",
            Region::WestIndia => "westindia",
            Region::CanadaCentral => "canadacentral",
            Region::CanadaEast => "canadaeast",
            Region::WestUs2 => "westus2",
            Region::WestCentralus => "westcentralus",
            Region::UkSouth => "uksouth",
            Region::UkWest => "ukwest",
            Region::KoreaCentral => "koreacentral",
            Region::KoreaSouth => "koreasouth",
            Region::FranceCentral => "francecentral",
            Region::SouthAfricaNorth => "southafricanorth",
            Region::UaeNorth => "uaenorth",
            Region::GermanyWestCentral => "germanywestcentral",
        }
    }
}

impl std::fmt::Display for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl std::str::FromStr for Region {
    type Err = Report;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            r if r == Region::EastUs.as_ref() => Region::EastUs,
            r if r == Region::EastUs2.as_ref() => Region::EastUs2,
            r if r == Region::WestUs.as_ref() => Region::WestUs,
            r if r == Region::CentralUs.as_ref() => Region::CentralUs,
            r if r == Region::NorthCentralUs.as_ref() => Region::NorthCentralUs,
            r if r == Region::SouthCentralUs.as_ref() => Region::SouthCentralUs,
            r if r == Region::NorthEurope.as_ref() => Region::NorthEurope,
            r if r == Region::WestEurope.as_ref() => Region::WestEurope,
            r if r == Region::EastUsia.as_ref() => Region::EastUsia,
            r if r == Region::SouthEastAsia.as_ref() => Region::SouthEastAsia,
            r if r == Region::JapanEast.as_ref() => Region::JapanEast,
            r if r == Region::JapanWest.as_ref() => Region::JapanWest,
            r if r == Region::AustraliaEast.as_ref() => Region::AustraliaEast,
            r if r == Region::AustraliaSoutheast.as_ref() => Region::AustraliaSoutheast,
            r if r == Region::AustraliaCentral.as_ref() => Region::AustraliaCentral,
            r if r == Region::BrazilSouth.as_ref() => Region::BrazilSouth,
            r if r == Region::SouthIndia.as_ref() => Region::SouthIndia,
            r if r == Region::CentralIndia.as_ref() => Region::CentralIndia,
            r if r == Region::WestIndia.as_ref() => Region::WestIndia,
            r if r == Region::CanadaCentral.as_ref() => Region::CanadaCentral,
            r if r == Region::CanadaEast.as_ref() => Region::CanadaEast,
            r if r == Region::WestUs2.as_ref() => Region::WestUs2,
            r if r == Region::WestCentralus.as_ref() => Region::WestCentralus,
            r if r == Region::UkSouth.as_ref() => Region::UkSouth,
            r if r == Region::UkWest.as_ref() => Region::UkWest,
            r if r == Region::KoreaCentral.as_ref() => Region::KoreaCentral,
            r if r == Region::KoreaSouth.as_ref() => Region::KoreaSouth,
            r if r == Region::FranceCentral.as_ref() => Region::FranceCentral,
            r if r == Region::SouthAfricaNorth.as_ref() => Region::SouthAfricaNorth,
            r if r == Region::UaeNorth.as_ref() => Region::UaeNorth,
            r if r == Region::GermanyWestCentral.as_ref() => Region::GermanyWestCentral,
            r => return Err(eyre!(r.to_string())).wrap_err("unknown azure region").suggestion("Valid regions: eastus, eastus2, westus, centralus, northcentralus, southcentralus, northeurope, westeurope, eastasia, southeastasia, japaneast, japanwest, australiaeast, australiasoutheast, australiacentral, brazilsouth, southindia, centralindia, westindia, canadacentral, canadaeast, westus2, westcentralus, uksouth, ukwest, koreacentral, koreasouth, francecentral, southafricanorth, uaenorth, germanywestcentral"),
        })
    }
}

mod azcmd {
    use super::IpInfo;
    use super::Region;
    use super::*;
    use serde::{Deserialize, Serialize};
    use tokio::process::Command;

    pub(crate) async fn check_az() -> Result<(), Report> {
        eyre::ensure!(
            Command::new("az").arg("account").arg("show").status().await.wrap_err("az account show")?.success(), 
            "Azure CLI not found. See https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest for installation, then run `az login`.",
        );
        Ok(())
    }

    #[instrument(level = "trace")]
    pub(crate) async fn create_resource_group(r: Region, name: &str) -> Result<(), Report> {
        let out = Command::new("az")
            .args(&[
                "group",
                "create",
                "--name",
                name,
                "--location",
                &r.to_string(),
            ])
            .status()
            .await
            .context("az group create")?;

        eyre::ensure!(out.success(), "failed to create resource group");
        Ok(())
    }

    #[instrument(level = "trace")]
    pub(crate) async fn create_vm(
        rg: &str,
        name: &str,
        size: &str,
        image: &str,
        username: &str,
    ) -> Result<IpInfo, Report> {
        #[allow(non_snake_case)]
        #[derive(Debug, Deserialize, Serialize)]
        struct VmCreateOut {
            powerState: String,
            publicIpAddress: String,
            privateIpAddress: String,
            resourceGroup: String,
        }

        let out = Command::new("az")
            .args(&[
                "vm",
                "create",
                "--resource-group",
                rg,
                "--name",
                name,
                "--image",
                image,
                "--size",
                size,
                "--admin-username",
                username,
                "--generate-ssh-keys",
            ])
            .output()
            .await
            .wrap_err("az vm create")?;

        eyre::ensure!(
            out.status.success(),
            "failed to create vm: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let vm: VmCreateOut = serde_json::from_slice(&out.stdout)?;
        eyre::ensure!(vm.powerState == "VM running", "VM power state incorrect");
        eyre::ensure!(vm.resourceGroup == rg, "VM resource group incorrect");
        Ok(IpInfo {
            public_ip: vm.publicIpAddress,
            private_ip: vm.privateIpAddress,
        })
    }

    #[instrument(level = "trace")]
    pub(crate) async fn open_ports(rg: &str, vm_name: &str) -> Result<(), Report> {
        let out = Command::new("az")
            .args(&[
                "vm",
                "open-port",
                "--port",
                "0-65535",
                "--resource-group",
                rg,
                "--name",
                vm_name,
            ])
            .output()
            .await
            .wrap_err("az vm open-port")?;

        eyre::ensure!(
            out.status.success(),
            "failed to open ports: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        Ok(())
    }

    #[instrument(level = "trace")]
    pub(crate) async fn delete_resource_group(rg: &str) -> Result<(), Report> {
        let out = Command::new("az")
            .args(&["group", "delete", "--name", rg, "--yes"])
            .status()
            .await
            .wrap_err("az group delete")?;

        eyre::ensure!(out.success(), "failed to delete resource group");

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::future::Future;

    #[test]
    #[ignore]
    fn azure_resource_group() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        static TEST_RG_NAME: &str = "test";
        rt.block_on(async move {
            azcmd::create_resource_group(Region::EastUs, TEST_RG_NAME)
                .await
                .expect("create resource group test failed");

            azcmd::delete_resource_group(TEST_RG_NAME)
                .await
                .expect("delete resource group failed");
        })
    }

    fn do_make_machine_and_ssh_setupfn<'l>(
        l: &'l mut super::Launcher,
    ) -> impl Future<Output = Result<(), Report>> + 'l {
        use crate::providers::{LaunchDescriptor, Launcher};
        let m = Setup::default().setup(|ssh| {
            Box::pin(async move {
                if ssh.command("whoami").status().await?.success() {
                    Ok(())
                } else {
                    Err(eyre!("failed"))
                }
            })
        });

        let ld = LaunchDescriptor {
            region: m.region,
            max_wait: None,
            machines: vec![("foo".to_owned(), m)],
        };

        async move {
            tracing::debug!("launching");
            l.launch(ld).await?;
            tracing::debug!("connecting");
            let vms = l.connect_all().await?;
            tracing::debug!("get machine");
            let my_machine = vms
                .get("foo")
                .ok_or_else(|| eyre::format_err!("machine not found"))?;
            tracing::debug!("running command");
            my_machine
                .ssh
                .command("echo")
                .arg("\"Hello, Azure\"")
                .status()
                .await?;

            Ok(())
        }
    }

    #[test]
    #[ignore]
    fn azure_launch_with_setupfn() {
        use crate::providers::Launcher;
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        let mut azure = super::Launcher::default();
        rt.block_on(async move {
            if let Err(e) = do_make_machine_and_ssh_setupfn(&mut azure).await {
                azure.terminate_all().await.unwrap();
                panic!(e);
            } else {
                azure.terminate_all().await.unwrap();
            }
        })
    }
}
