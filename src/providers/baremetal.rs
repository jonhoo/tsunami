use crate::ssh;
use failure::Error;
use std::collections::HashMap;
use std::time;

pub struct Setup {
    addr: std::net::SocketAddr,
    username: String,
    key_path: Option<std::path::PathBuf>,
    setup_fn: Option<Box<dyn Fn(&mut ssh::Session, &slog::Logger) -> Result<(), Error> + Sync>>,
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
    pub fn new(addr: impl std::net::ToSocketAddrs, username: String) -> Result<Self, Error> {
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
        setup: impl Fn(&mut ssh::Session, &slog::Logger) -> Result<(), Error> + Sync + 'static,
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

unsafe impl Send for Machine {}

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
                    setup
                        .key_path
                        .as_ref()
                        .unwrap_or(&std::path::Path::new("~/.ssh/id_rsa").to_path_buf()),
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
