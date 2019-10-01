use crate::ssh;
use failure::Error;
use std::collections::HashMap;

/// Descriptor for a single, existing machine to connect to.
/// Therefore, the `impl MachineSetup` includes the address of the machine in `region`; i.e.,
/// each instance of Setup corresponds to a single machine.
pub struct Setup {
    addr: std::net::SocketAddr,
    username: String,
    key_path: Option<std::path::PathBuf>,
    setup_fn:
        Option<Box<dyn Fn(&mut ssh::Session, &slog::Logger) -> Result<(), Error> + Send + Sync>>,
}

impl super::MachineSetup for Setup {
    type Region = String;
    fn region(&self) -> Self::Region {
        format!("bare:{}", self.addr)
    }
}

impl PartialEq for Setup {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

impl Eq for Setup {}

impl std::hash::Hash for Setup {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
    }
}

impl Setup {
    pub fn new(
        addr: impl std::net::ToSocketAddrs,
        username: Option<String>,
    ) -> Result<Self, Error> {
        let username: Result<String, Error> = username.map(Ok).unwrap_or_else(|| {
            let user = String::from_utf8(std::process::Command::new("whoami").output()?.stdout)?;
            let user = user
                .split_whitespace()
                .next()
                .expect("expect newline after whoami output");
            Ok(user.to_string())
        });
        let username = username?;

        Ok(Self {
            username,
            addr: addr
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| format_err!("No socket addresses found"))?,
            key_path: None,
            setup_fn: None,
        })
    }

    pub fn key_path(self, p: impl AsRef<std::path::Path>) -> Self {
        Self {
            key_path: Some(p.as_ref().to_path_buf()),
            ..self
        }
    }

    pub fn setup(
        self,
        setup: impl Fn(&mut ssh::Session, &slog::Logger) -> Result<(), Error> + Send + Sync + 'static,
    ) -> Self {
        Self {
            setup_fn: Some(Box::new(setup)),
            ..self
        }
    }
}

/// Only one machine is supported per instance of this Launcher, further instances of `Setup`
/// passed to `init_instances` will
/// be ignored, since it doesn't make sense to connect to the same machine twice.
///
/// The `impl Drop` of this type is a no-op, since Tsunami can't terminate an existing machine.
#[derive(Default)]
pub struct Machine {
    pub log: Option<slog::Logger>,
    name: String,
    addr: Option<std::net::SocketAddr>,
    username: String,
    key_path: Option<std::path::PathBuf>,
}

impl super::Launcher for Machine {
    type Region = String;
    type Machine = Setup;

    fn region(&self) -> Self::Region {
        String::from("bare")
    }

    fn launch(
        &mut self,
        l: super::LaunchDescriptor<Self::Machine, Self::Region>,
    ) -> Result<(), Error> {
        self.log = Some(l.log);
        let log = self.log.as_ref().expect("Baremetal machine uninitialized");
        let dscs = l
            .machines
            .into_iter()
            .collect::<Vec<(String, Self::Machine)>>();
        if dscs.is_empty() {
            bail!("Cannot initialize zero machines");
        }

        if dscs.len() > 1 {
            warn!(log, "Discarding duplicate connections to same machine";
                "name" => &dscs[0].0,
                "addr" => &dscs[0].1.addr,
            );
        }

        let (name, setup) = dscs.into_iter().next().unwrap();

        let mut sess = ssh::Session::connect(
            log,
            &setup.username,
            setup.addr,
            setup.key_path.as_ref().map(|p| p.as_path()),
            l.max_wait,
        )
        .map_err(|e| {
            error!(log, "failed to ssh to {}", &setup.addr);
            e.context(format!("failed to ssh to machine {}", setup.addr))
        })?;

        if let Setup {
            setup_fn: Some(f), ..
        } = setup
        {
            f(&mut sess, log).map_err(|e| {
                error!(
                    log,
                    "machine setup failed";
                    "name" => name.clone(),
                );
                e.context(format!("setup procedure for {} machine failed", name))
            })?;
        }

        info!(log, "finished setting up instance"; "name" => &name, "ip" => &setup.addr);
        self.name = name;
        self.addr = Some(setup.addr);
        self.username = setup.username;
        self.key_path = setup.key_path;
        Ok(())
    }

    fn connect_instances<'l>(&'l self) -> Result<HashMap<String, crate::Machine<'l>>, Error> {
        let log = self.log.as_ref().expect("Baremetal machine uninitialized");
        let addr = self
            .addr
            .ok_or_else(|| format_err!("Address uninitialized"))?;
        let sess = ssh::Session::connect(
            log,
            &self.username,
            addr,
            self.key_path.as_ref().map(|p| p.as_path()),
            None,
        )
        .map_err(|e| {
            error!(log, "failed to ssh to {}", &addr);
            e.context(format!("failed to ssh to machine {}", addr))
        })?;

        let mut hmap: HashMap<String, crate::Machine<'l>> = Default::default();
        hmap.insert(
            self.name.clone(),
            crate::Machine {
                nickname: self.name.clone(),
                public_dns: addr.to_string(),
                public_ip: addr.ip().to_string(),
                ssh: Some(sess),
                _tsunami: Default::default(),
            },
        );
        Ok(hmap)
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        let log = self.log.as_ref().expect("Baremetal machine uninitialized");
        debug!(log, "Dropping baremetal machine");
    }
}

// TODO not working due to some ssh-agent bug:
// ---- providers::baremetal::test::localhost stdout ----
// Aug 29 18:59:42.375 TRCE agent identity failed, err: Error { code: -18, msg: "Username/PublicKey
// combination invalid" }, identity: /Users/akshay/.ssh/id_rsa, username: akshay
//
// Aug 29 18:59:42.375 ERRO failed to ssh to [::1]:22
// Error: ErrorMessage { msg: "failed to authenticate ssh session with ssh-agent" }
#[cfg(test)]
mod test {
    use crate::providers::Launcher;
    use failure::Error;

    #[test]
    #[ignore]
    fn localhost() -> Result<(), Error> {
        let s = super::Setup::new("127.0.0.1:22", None)?;
        let mut m: super::Machine = Default::default();
        m.log = Some(crate::test::test_logger());
        let desc = crate::providers::LaunchDescriptor {
            region: String::from("localhost"),
            log: crate::test::test_logger(),
            max_instance_duration: None,
            max_wait: None,
            machines: vec![(String::from("self"), s)],
        };
        m.launch(desc)?;
        let ms = m.connect_instances()?;
        ms.get("self")
            .unwrap()
            .ssh
            .as_ref()
            .unwrap()
            .cmd("ls")
            .unwrap();
        Ok(())
    }
}
