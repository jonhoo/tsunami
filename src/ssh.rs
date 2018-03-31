use async_ssh;
use failure::{Error, ResultExt};
use futures::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};
use thrussh_keys;
use tokio_core;
use tokio_io;

/// An established SSH session.
///
/// See [`ssh2::Session`](https://docs.rs/ssh2/0.3/ssh2/struct.Session.html) in general, and
/// [`ssh2::Session#channel_session`](https://docs.rs/ssh2/0.3/ssh2/struct.Session.html#method.channel_session)
/// specifically, for how to execute commands on the remote host.
///
/// To execute a command and get its `STDOUT` output, use
/// [`Session#cmd`](struct.Session.html#method.cmd).
pub struct Session {
    ssh: async_ssh::Session<tokio_core::net::TcpStream>,
}

impl Session {
    pub(crate) fn connect<'a>(
        username: &'a str,
        addr: SocketAddr,
        key: &Path,
        handle: &'a tokio_core::reactor::Handle,
    ) -> Box<Future<Item = Self, Error = Error> + 'a> {
        // TODO: instead of max time, keep trying as long as instance is still active
        let start = Instant::now();
        let key = thrussh_keys::load_secret_key(key, None).unwrap();
        // TODO: retry tcp connection

        Box::new(
            tokio_core::net::TcpStream::connect(&addr, handle)
                .then(|r| r.context("failed to connect to ssh port"))
                .map_err(Into::into)
                .and_then(move |c| {
                    async_ssh::Session::new(c, &handle)
                        .map_err(|e| format_err!("{:?}", e))
                        .context("failed to establish ssh session")
                })
                .and_then(move |session| {
                    session
                        .authenticate_key(username, key)
                        .map_err(|e| format_err!("{:?}", e))
                        .then(|r| r.context("failed to authenticate ssh session"))
                })
                .map_err(Into::into)
                .map(|ssh| Session { ssh }),
        )
    }

    /// Issue the given command and return the command's raw standard output.
    pub fn cmd_raw<'a>(&mut self, cmd: &'a str) -> Box<Future<Item = Vec<u8>, Error = Error> + 'a> {
        // TODO: check channel.exit_status()
        // TODO: return stderr as well?
        Box::new(
            self.ssh
                .open_exec(cmd)
                .map_err(|e| format_err!("{:?}", e))
                .then(move |e| {
                    e.map_err(|e| format_err!("{:?}", e))
                        .context(format!("failed to execute command '{}'", cmd))
                })
                .map_err(Into::into)
                .and_then(move |c| {
                    tokio_io::io::read_to_end(c, Vec::new()).then(move |r| {
                        r.context(format!("failed to read stdout of command '{}'", cmd))
                    })
                })
                .map(|(_, b)| b)
                .map_err(Into::into),
        )
    }

    /// Issue the given command and return the command's standard output.
    pub fn cmd<'a>(&mut self, cmd: &'a str) -> Box<Future<Item = String, Error = Error> + 'a> {
        Box::new(self.cmd_raw(cmd).and_then(|bytes| {
            String::from_utf8(bytes)
                .context("invalid utf-8 in command output")
                .map_err(Into::into)
        }))
    }
}

use std::ops::{Deref, DerefMut};
impl Deref for Session {
    type Target = async_ssh::Session<tokio_core::net::TcpStream>;
    fn deref(&self) -> &Self::Target {
        &self.ssh
    }
}

impl DerefMut for Session {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ssh
    }
}
