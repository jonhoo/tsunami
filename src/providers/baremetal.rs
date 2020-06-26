//! Baremetal backend for tsunami.
//!
//! Use this to use machines that already exist.

use color_eyre::{
    eyre::{self, eyre, WrapErr},
    Report,
};
use educe::Educe;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tracing::instrument;
use tracing_futures::Instrument;

/// Descriptor for a single, existing machine to connect to.
/// Therefore, the `impl MachineSetup` includes the address of the machine in `region`; i.e.,
/// each instance of Setup corresponds to a single machine.
#[derive(Clone, Educe)]
#[educe(Debug)]
pub struct Setup {
    addr: Vec<std::net::SocketAddr>,
    username: String,
    key_path: Option<std::path::PathBuf>,
    #[educe(Debug(ignore))]
    setup_fn: Option<
        Arc<
            dyn for<'r> Fn(
                    &'r crate::Machine<'_>,
                )
                    -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'r>>
                + Send
                + Sync
                + 'static,
        >,
    >,
}

impl super::MachineSetup for Setup {
    type Region = String;
    fn region(&self) -> Self::Region {
        format!("bare:{}", self.addr[0])
    }
}

impl Setup {
    /// Create a new instance of Setup.
    #[instrument(level = "debug")]
    pub fn new<A: std::net::ToSocketAddrs + std::fmt::Debug>(
        addr: A,
        username: Option<String>,
    ) -> Result<Self, Report> {
        let username: Result<String, Report> = username.map(Ok).unwrap_or_else(|| {
            let stdout = std::process::Command::new("whoami")
                .output()
                .wrap_err("failed to execute whoami to determine local user")?
                .stdout;
            let user = String::from_utf8_lossy(&stdout);
            tracing::trace!(username = %user, "re-using local username");
            let user = user
                .split_whitespace()
                .next()
                .expect("expect newline after whoami output");
            Ok(user.to_string())
        });
        let username = username?;
        let mut addr: Vec<std::net::SocketAddr> = addr.to_socket_addrs()?.collect();
        addr.reverse(); // so pop() will reutrn in the same order

        Ok(Self {
            username,
            addr,
            key_path: None,
            setup_fn: None,
        })
    }

    /// Set the location of the user's key.
    pub fn key_path(self, p: impl AsRef<std::path::Path>) -> Self {
        Self {
            key_path: Some(p.as_ref().to_path_buf()),
            ..self
        }
    }

    /// Specify instance setup.
    ///
    /// The provided callback, `setup`, is called once
    /// for every spawned instances of this type with a handle
    /// to the target machine. Use [`crate::Machine::ssh`] to issue
    /// commands on the host in question.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tsunami::providers::baremetal::Setup;
    /// let m = Setup::new("127.0.0.1:22", None).unwrap().setup(|vm| {
    ///     Box::pin(async move {
    ///         vm.ssh
    ///             .command("sudo")
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
                &'r crate::Machine<'_>,
            ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'r>>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.setup_fn = Some(Arc::new(setup));
        self
    }
}

#[instrument(level = "trace", skip(s, max_wait))]
async fn try_addrs(
    s: &mut Setup,
    max_wait: Option<std::time::Duration>,
) -> Result<std::net::SocketAddr, Report> {
    let mut errs = Vec::new();
    while let Some(addr) = s.addr.pop() {
        let host_span = tracing::debug_span!("host", host = %addr);
        let ret = async {
            tracing::trace!("testing address");

            let m = crate::MachineDescriptor {
                nickname: Default::default(),
                public_dns: None,
                public_ip: addr.ip().to_string(),
                private_ip: None,
                _tsunami: Default::default(),
            };

            match m
                .connect_ssh(&s.username, s.key_path.as_deref(), max_wait, addr.port())
                .await
            {
                Err(e) => {
                    errs.push(eyre!(e));
                    None
                }
                Ok(_) => Some(addr),
            }
        }
        .instrument(host_span)
        .await;

        if let Some(addr) = ret {
            return Ok(addr);
        }
    }

    if errs.is_empty() {
        eyre::bail!("no known addresses");
    }

    // we have potentially many errors, and we need to return one.
    // not clear what to do about that.. we're just going to chain them for now.
    let mut err = Err(errs.pop().unwrap());
    while let Some(e) = errs.pop() {
        // the first address will end up "outermost", which is probably fine
        err = err.wrap_err(e);
    }
    err
}

/// Only one machine is supported per instance of this Launcher, further instances of `Setup`
/// passed to `launch` will
/// be ignored, since it doesn't make sense to connect to the same machine twice.
///
/// The `impl Drop` of this type is a no-op, since Tsunami can't terminate an existing machine.
#[derive(Debug, Default)]
pub struct Machine {
    name: String,
    addr: Option<std::net::SocketAddr>,
    username: String,
    key_path: Option<std::path::PathBuf>,
}

impl super::Launcher for Machine {
    type MachineDescriptor = Setup;

    #[instrument(level = "debug", skip(self))]
    fn launch<'l>(
        &'l mut self,
        l: super::LaunchDescriptor<Self::MachineDescriptor>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'l>> {
        Box::pin(async move {
            let mut dscs = l.machines.into_iter();
            let (name, mut setup) = dscs
                .next()
                .ok_or_else(|| eyre!("Cannot initialize zero machines"))?;
            for (discarded_name, discarded_setup) in dscs {
                tracing::warn!(
                    name = %discarded_name,
                    addr = %discarded_setup.addr[0],
                    "Discarding duplicate connections to same machine",
                );
            }

            let addr = try_addrs(&mut setup, l.max_wait)
                .await
                .wrap_err("failed to find valid baremetal address")?;

            if let Setup {
                ref username,
                ref key_path,
                setup_fn: Some(ref f),
                ..
            } = setup
            {
                let m = crate::MachineDescriptor {
                    nickname: Default::default(),
                    public_dns: None,
                    public_ip: addr.ip().to_string(),
                    private_ip: None,
                    _tsunami: Default::default(),
                };

                let mut m = m
                    .connect_ssh(&username, key_path.as_deref(), l.max_wait, addr.port())
                    .await?;

                f(&mut m).await.wrap_err("setup procedure failed")?;
            }

            tracing::info!("instance ready");
            self.name = name;
            self.addr = Some(addr);
            self.username = setup.username;
            self.key_path = setup.key_path;
            Ok(())
        })
    }

    #[instrument(level = "debug")]
    fn connect_all<'l>(
        &'l self,
    ) -> Pin<
        Box<dyn Future<Output = Result<HashMap<String, crate::Machine<'l>>, Report>> + Send + 'l>,
    > {
        Box::pin(async move {
            let addr = self.addr.ok_or_else(|| eyre!("Address uninitialized"))?;
            let m = crate::MachineDescriptor {
                nickname: self.name.clone(),
                public_dns: None,
                public_ip: addr.ip().to_string(),
                private_ip: None,
                _tsunami: Default::default(),
            };

            let m = m
                .connect_ssh(&self.username, self.key_path.as_deref(), None, addr.port())
                .await?;

            let mut hmap: HashMap<String, crate::Machine<'l>> = Default::default();
            hmap.insert(self.name.clone(), m);
            Ok(hmap)
        })
    }

    fn terminate_all(self) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send>> {
        Box::pin(async move { Ok(()) })
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        tracing::trace!(addr = ?self.addr, "dropping baremetal instance");
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::providers::Launcher;

    #[test]
    #[ignore]
    fn localhost() -> Result<(), Report> {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        let s = super::Setup::new("127.0.0.1:22", None)?;
        let mut m: super::Machine = Default::default();
        let desc = crate::providers::LaunchDescriptor {
            region: String::from("localhost"),
            max_wait: None,
            machines: vec![(String::from("self"), s)],
        };
        rt.block_on(async move {
            m.launch(desc).await?;
            let ms = m.connect_all().await?;
            assert!(ms
                .get("self")
                .unwrap()
                .ssh
                .command("ls")
                .status()
                .await
                .unwrap()
                .success());
            Ok(())
        })
    }
}
