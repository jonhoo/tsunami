//! Azure backend for tsunami.
//!
//! The primary `impl Launcher` type is [`Launcher`].
//! It internally uses the lower-level, region-specific [`azure::RegionLauncher`].
//! Both these types use [`azure::Setup`] as their descriptor type.
//!
//! Azure does not support Spot or Defined Duration instances.
//! As a result, if your tsunami crashes (i.e., exits without calling `drop()` on [`Launcher`], you must manually terminate your instances
//! to avoid extra costs.
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
//! use tsunami::providers::{azure, Launcher};
//! use tsunami::TsunamiBuilder;
//!
//! let mut b = TsunamiBuilder::default();
//! b.add("my machine", azure::Setup::default()).unwrap();
//! let mut l = azure::Launcher::default();
//! b.spawn(&mut l).unwrap();
//! let vms = l.connect_all().unwrap();
//! let my_machine = vms.get("my machine").unwrap();
//! let (stdout, stderr) = my_machine.ssh.as_ref().unwrap().cmd("echo \"Hello, Azure\"").unwrap();
//! println!("{}", stdout);
//! ```

use crate::ssh;
use educe::Educe;
use failure::{bail, Error};
use std::collections::HashMap;
use std::sync::Arc;

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
    setup_fn:
        Option<Arc<dyn Fn(&mut ssh::Session, &slog::Logger) -> Result<(), Error> + Send + Sync>>,
}

impl Default for Setup {
    fn default() -> Self {
        Setup {
            region: "eastus".parse().unwrap(),
            instance_type: "Standard_DS1_v2".to_string(),
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
    /// `az vm list-sizes -l <region_name>`.
    pub fn instance_type(mut self, inst_type: String) -> Self {
        self.instance_type = inst_type;
        self
    }

    /// Set the image.
    ///
    /// See `az vm image list` for valid options.
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
    /// let m = Setup::default()
    ///     .setup(|ssh, log| {
    ///         slog::info!(log, "running setup!");
    ///         ssh.cmd("sudo apt update")?;
    ///         Ok(())
    ///     });
    /// ```
    pub fn setup(
        mut self,
        setup: impl Fn(&mut ssh::Session, &slog::Logger) -> Result<(), Error> + Send + Sync + 'static,
    ) -> Self {
        self.setup_fn = Some(Arc::new(setup));
        self
    }
}

/// Launcher type for the Microsoft Azure cloud.
///
/// This implementation relies on the [Azure
/// CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest).
///
/// It also assumes you have previously run `az login` to authenticate.
#[derive(Debug, Default)]
pub struct Launcher {
    regions: HashMap<Region, RegionLauncher>,
}

impl super::Launcher for Launcher {
    type MachineDescriptor = Setup;

    fn launch(&mut self, l: super::LaunchDescriptor<Self::MachineDescriptor>) -> Result<(), Error> {
        let region = l.region;
        let mut az_region = RegionLauncher::new(l.region, l.log.clone())?;
        az_region.launch(l)?;
        self.regions.insert(region, az_region);
        Ok(())
    }

    fn connect_all<'l>(&'l self) -> Result<HashMap<String, crate::Machine<'l>>, Error> {
        collect!(self.regions)
    }
}

#[derive(Debug)]
struct Descriptor {
    name: String,
    username: String,
    ip: String,
}

/// Region-specific connection to Azure.
///
/// Each instance of this type creates one Azure
/// "resource group" and deletes the group on drop.
///
/// This implementation relies on the [Azure
/// CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest).
/// It also assumes you have previously run `az login` to authenticate with Microsoft.
#[derive(Debug, Default)]
pub struct RegionLauncher {
    /// A logger.
    pub log: Option<slog::Logger>,
    /// The region this [`RegionLauncher`] is connected to.
    pub region: Region,
    resource_group_name: String,
    machines: Vec<Descriptor>,
}

impl RegionLauncher {
    /// Create a new instance of RegionLauncher.
    pub fn new(region: Region, log: slog::Logger) -> Result<Self, Error> {
        let rg_name = super::rand_name("resourcegroup");

        azcmd::create_resource_group(region, &rg_name)?;

        Ok(Self {
            log: Some(log),
            region,
            resource_group_name: rg_name,
            machines: vec![],
        })
    }
}

impl super::Launcher for RegionLauncher {
    type MachineDescriptor = Setup;

    fn launch(&mut self, l: super::LaunchDescriptor<Self::MachineDescriptor>) -> Result<(), Error> {
        self.log = Some(l.log);
        let log = self.log.as_ref().unwrap();
        let max_wait = l.max_wait;
        let vms: Result<Vec<(String, String, _)>, Error> = l.machines
            .into_iter()
            .map(|(nickname, desc)| {
                let vm_name = super::rand_name_sep("vm", "-");
                debug!(log, "setting up azure instance"; "nickname" => &nickname, "vm_name" => &vm_name);

                let pub_ip = azcmd::create_vm(
                    &self.resource_group_name,
                    &vm_name,
                    &desc.instance_type,
                    &desc.image,
                    &desc.username,
                )?;

                azcmd::open_ports(&self.resource_group_name, &vm_name)?;

                Ok((nickname, pub_ip, desc))
            }).collect();

        use rayon::prelude::*;
        self.machines = vms?
            .into_par_iter()
            .map(|(nickname, pub_ip, desc)| {
                if let Setup {
                    ref username,
                    setup_fn: Some(ref f),
                    ..
                } = desc
                {
                    super::setup_machine(
                        log,
                        &nickname,
                        &pub_ip,
                        &username,
                        max_wait,
                        None,
                        f.as_ref(),
                    )?;
                }

                Ok(Descriptor {
                    name: nickname,
                    username: desc.username,
                    ip: pub_ip,
                })
            })
            .collect::<Result<Vec<Descriptor>, Error>>()?;

        Ok(())
    }

    fn connect_all<'l>(&'l self) -> Result<HashMap<String, crate::Machine<'l>>, Error> {
        let log = self.log.as_ref().expect("RegionLauncher uninitialized");
        self.machines
            .iter()
            .map(|desc| {
                let Descriptor { name, username, ip } = desc;
                let mut m = crate::Machine {
                    nickname: name.clone(),
                    public_dns: ip.clone(),
                    public_ip: ip.clone(),
                    ssh: None,
                    _tsunami: Default::default(),
                };

                m.connect_ssh(log, username, None)?;
                Ok((name.clone(), m))
            })
            .collect()
    }
}

impl Drop for RegionLauncher {
    fn drop(&mut self) {
        debug!(self.log.as_ref().unwrap(), "Cleaning up resource group");
        azcmd::delete_resource_group(&self.resource_group_name).unwrap();
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
    SouthEastUsia,
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

impl ToString for Region {
    fn to_string(&self) -> String {
        String::from(match self {
            Region::EastUs => "eastus",
            Region::EastUs2 => "eastus2",
            Region::WestUs => "westus",
            Region::CentralUs => "centralus",
            Region::NorthCentralUs => "northcentralus",
            Region::SouthCentralUs => "southcentralus",
            Region::NorthEurope => "northeurope",
            Region::WestEurope => "westeurope",
            Region::EastUsia => "eastasia",
            Region::SouthEastUsia => "southeastasia",
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
        })
    }
}

impl std::str::FromStr for Region {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "eastus" => Region::EastUs,
            "eastus2" => Region::EastUs2,
            "westus" => Region::WestUs,
            "centralus" => Region::CentralUs,
            "northcentralus" => Region::NorthCentralUs,
            "southcentralus" => Region::SouthCentralUs,
            "northeurope" => Region::NorthEurope,
            "westeurope" => Region::WestEurope,
            "eastasia" => Region::EastUsia,
            "southeastasia" => Region::SouthEastUsia,
            "japaneast" => Region::JapanEast,
            "japanwest" => Region::JapanWest,
            "australiaeast" => Region::AustraliaEast,
            "australiasoutheast" => Region::AustraliaSoutheast,
            "australiacentral" => Region::AustraliaCentral,
            "brazilsouth" => Region::BrazilSouth,
            "southindia" => Region::SouthIndia,
            "centralindia" => Region::CentralIndia,
            "westindia" => Region::WestIndia,
            "canadacentral" => Region::CanadaCentral,
            "canadaeast" => Region::CanadaEast,
            "westus2" => Region::WestUs2,
            "westcentralus" => Region::WestCentralus,
            "uksouth" => Region::UkSouth,
            "ukwest" => Region::UkWest,
            "koreacentral" => Region::KoreaCentral,
            "koreasouth" => Region::KoreaSouth,
            "francecentral" => Region::FranceCentral,
            "southafricanorth" => Region::SouthAfricaNorth,
            "uaenorth" => Region::UaeNorth,
            "germanywestcentral" => Region::GermanyWestCentral,
            u => bail!("Unknown azure region {}", u),
        })
    }
}

mod azcmd {
    use super::Error;
    use super::Region;
    use failure::ResultExt;
    use serde::{Deserialize, Serialize};
    use std::process::Command;

    pub(crate) fn create_resource_group(r: Region, name: &str) -> Result<(), Error> {
        let out = Command::new("az")
            .args(&[
                "group",
                "create",
                "--name",
                name,
                "--location",
                &r.to_string(),
            ])
            .output()?;

        if !out.status.success() {
            bail!("Failed to create resource group {} in region {:?}", name, r)
        }

        Ok(())
    }

    pub(crate) fn create_vm(
        rg: &str,
        name: &str,
        size: &str,
        image: &str,
        username: &str,
    ) -> Result<String, Error> {
        #[allow(non_snake_case)]
        #[derive(Debug, Deserialize, Serialize)]
        struct VmCreateOut {
            powerState: String,
            publicIpAddress: String,
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
                "--ssh-key-value",
                "@~/.ssh/id_rsa.pub",
            ])
            .output()?;

        if !out.status.success() {
            return Err(format_err!("Failed to create vm {}", name))
                .context(String::from_utf8(out.stderr).unwrap())?;
        }

        let vm: VmCreateOut = serde_json::from_slice(&out.stdout)?;
        ensure!(vm.powerState == "VM running", "VM power state incorrect");
        ensure!(vm.resourceGroup == rg, "VM resource group incorrect");
        Ok(vm.publicIpAddress)
    }

    pub(crate) fn open_ports(rg: &str, vm_name: &str) -> Result<(), Error> {
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
            .output()?;
        if !out.status.success() {
            return Err(format_err!("Failed to open ports for {}", vm_name))
                .context(String::from_utf8(out.stderr).unwrap())?;
        }

        Ok(())
    }

    pub(crate) fn delete_resource_group(rg: &str) -> Result<(), Error> {
        let out = Command::new("az")
            .args(&["group", "delete", "--name", rg, "--yes"])
            .output()?;
        if !out.status.success() {
            bail!("Failed to delete resource group {}", rg)
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::azcmd;
    use super::Region;

    #[test]
    #[ignore]
    fn resource_group() {
        static TEST_RG_NAME: &str = "test";
        azcmd::create_resource_group(Region::EastUs, TEST_RG_NAME)
            .expect("create resource group test failed");

        azcmd::delete_resource_group(TEST_RG_NAME).expect("delete resource group failed");
    }
}
