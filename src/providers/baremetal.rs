use crate::ssh;
use failure::Error;
use std::collections::HashMap;
use std::time;

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
            Ok(String::from_utf8(
                std::process::Command::new("whoami").output()?.stdout,
            )?)
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

pub struct Machine {
    pub log: slog::Logger,
}

impl super::Launcher for Machine {
    type Region = String;
    type Machine = Setup;

    fn region(&self) -> Self::Region {
        String::from("bare")
    }

    fn init_instances(
        &mut self,
        _max_instance_duration: Option<time::Duration>,
        max_wait: Option<time::Duration>,
        machines: impl IntoIterator<Item = (String, Self::Machine)>,
    ) -> Result<HashMap<String, crate::Machine>, Error> {
        machines
            .into_iter()
            .map(|(name, setup)| {
                let mut sess = ssh::Session::connect(
                    &self.log,
                    &setup.username,
                    setup.addr,
                    setup.key_path.as_ref().map(|p| p.as_path()),
                    max_wait,
                )
                .map_err(|e| {
                    error!(self.log, "failed to ssh to {}", &setup.addr);
                    e.context(format!("failed to ssh to machine {}", setup.addr))
                })?;

                match setup {
                    Setup {
                        setup_fn: Some(f), ..
                    } => {
                        f(&mut sess, &self.log).map_err(|e| {
                            error!(
                                self.log,
                                "machine setup failed";
                                "name" => name.clone(),
                            );
                            e.context(format!("setup procedure for {} machine failed", name))
                        })?;
                    }
                    _ => {}
                }

                info!(self.log, "finished setting up {} instance", name; "ip" => &setup.addr);

                Ok((
                    name.clone(),
                    crate::Machine {
                        nickname: name,
                        public_dns: setup.addr.to_string(),
                        public_ip: setup.addr.ip().to_string(),
                        ssh: Some(sess),
                    },
                ))
            })
            .collect()
    }
}

// TODO not working due to some ssh-agent bug:
// ---- providers::baremetal::test::localhost stdout ----
// Aug 29 18:59:42.375 TRCE agent identity failed, err: Error { code: -18, msg: "Username/PublicKey
// combination invalid" }, identity: /Users/akshay/.ssh/id_rsa, username: akshay
//
// Aug 29 18:59:42.375 ERRO failed to ssh to [::1]:22
// Error: ErrorMessage { msg: "failed to authenticate ssh session with ssh-agent" }
/*
#[cfg(test)]
mod test {
    use crate::providers::Launcher;
    use failure::Error;

    #[test]
    fn localhost() -> Result<(), Error> {
        let s = super::Setup::new("localhost:22", None)?;
        let mut m = super::Machine {
            log: crate::test::test_logger(),
        };
        let ms = m.init_instances(None, None, vec![(String::from("self"), s)])?;
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
*/
