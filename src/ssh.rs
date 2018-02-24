use ssh2;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};
use std::thread;
use failure::ResultExt;
use failure::{Context, Error};

/// An established SSH session.
pub struct Session {
    ssh: ssh2::Session,
    _stream: TcpStream,
}

impl Session {
    pub(crate) fn connect(addr: SocketAddr, key: &Path) -> Result<Self, Error> {
        // TODO: instead of max time, keep trying as long as instance is still active
        let start = Instant::now();
        let tcp = loop {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                Ok(s) => break s,
                Err(_) if start.elapsed() <= Duration::from_secs(120) => {
                    thread::sleep(Duration::from_secs(1));
                }
                Err(e) => Err(Error::from(e).context("failed to connect to ssh port"))?,
            }
        };

        let mut sess = ssh2::Session::new().ok_or(Context::new("libssh2 not available"))?;
        sess.handshake(&tcp)
            .context("failed to perform ssh handshake")?;
        sess.userauth_pubkey_file("ec2-user", None, key, None)
            .context("failed to authenticate ssh session")?;

        Ok(Session {
            ssh: sess,
            _stream: tcp,
        })
    }

    /// Issue the given command and return the command standard output.
    pub fn cmd(&mut self, cmd: &str) -> Result<String, Error> {
        use std::io::Read;

        let mut channel = self.ssh
            .channel_session()
            .map_err(Error::from)
            .map_err(|e| {
                e.context(format!(
                    "failed to create ssh channel for command '{}'",
                    cmd
                ))
            })?;

        channel
            .exec(cmd)
            .map_err(Error::from)
            .map_err(|e| e.context(format!("failed to execute command '{}'", cmd)))?;

        let mut s = String::new();
        channel
            .read_to_string(&mut s)
            .map_err(Error::from)
            .map_err(|e| e.context(format!("failed to read results of command '{}'", cmd)))?;

        channel
            .wait_close()
            .map_err(Error::from)
            .map_err(|e| e.context(format!("command '{}' never completed", cmd)))?;

        // TODO: check channel.exit_status()
        Ok(s)
    }
}

use std::ops::{Deref, DerefMut};
impl Deref for Session {
    type Target = ssh2::Session;
    fn deref(&self) -> &Self::Target {
        &self.ssh
    }
}

impl DerefMut for Session {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ssh
    }
}
