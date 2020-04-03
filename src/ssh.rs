use failure::Error;
use failure::Fail;
use failure::ResultExt;
use slog;
use ssh2;
use std::fs::File;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Fail)]
#[fail(display = "error transferring file {}: {}", file, msg)]
struct FileTransferFailure {
    file: String,
    msg: String,
}

/// An established SSH session.
///
/// See [`ssh2::Session`](https://docs.rs/ssh2/0.3/ssh2/struct.Session.html) in general, and
/// [`ssh2::Session#channel_session`](https://docs.rs/ssh2/0.3/ssh2/struct.Session.html#method.channel_session)
/// specifically, for how to execute commands on the remote host.
///
/// To execute a command and get its `STDOUT` output, use
/// [`Session#cmd`](struct.Session.html#method.cmd).
pub struct Session {
    ssh: ssh2::Session,
}

impl Session {
    pub(crate) fn connect(
        log: &slog::Logger,
        username: &str,
        addr: SocketAddr,
        key: &Path,
        timeout: Option<Duration>,
    ) -> Result<Self, Error> {
        // TODO: instead of max time, keep trying as long as instance is still active
        let start = Instant::now();
        let tcp = loop {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                Ok(s) => break s,
                Err(e) => {
                    if let Some(to) = timeout {
                        if start.elapsed() <= to {
                            thread::sleep(Duration::from_secs(1));
                        } else {
                            Err(Error::from(e).context("failed to connect to ssh port"))?;
                        }
                    } else {
                        if start.elapsed() > Duration::from_secs(30) {
                            warn!(log, "still can't ssh to {}: {:?}", addr, e);
                        }
                    }
                }
            }
        };

        let mut sess = ssh2::Session::new().context("libssh2 not available")?;
        sess.set_tcp_stream(tcp);
        sess.handshake()
            .context("failed to perform ssh handshake")?;
        sess.userauth_pubkey_file(username, None, key, None)
            .context("failed to authenticate ssh session")?;

        Ok(Session { ssh: sess })
    }

    /// Issue the given command and return the command's raw standard output.
    pub fn cmd_raw(&self, cmd: &str) -> Result<Vec<u8>, Error> {
        use std::io::Read;

        let mut channel = self
            .ssh
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

        channel
            .send_eof()
            .map_err(Error::from)
            .map_err(|e| e.context(format!("failed to finish command '{}'", cmd)))?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        // NOTE: the loop is needed because libssh2 can return reads of size 0 without EOF
        // https://www.libssh2.org/libssh2_channel_read_ex.html
        // NOTE: we must read from *both* stdout and stderr. EOF is only sent when they're both
        // drained.
        while !channel.eof() {
            channel
                .read_to_end(&mut stdout)
                .map_err(Error::from)
                .map_err(|e| e.context(format!("failed to read stdout of command '{}'", cmd)))?;
            channel
                .stderr()
                .read_to_end(&mut stderr)
                .map_err(Error::from)
                .map_err(|e| e.context(format!("failed to read stderr of command '{}'", cmd)))?;
        }

        channel
            .wait_close()
            .map_err(Error::from)
            .map_err(|e| e.context(format!("command '{}' never completed", cmd)))?;

        // TODO: check channel.exit_status()
        // TODO: return stderr as well?
        drop(stderr);
        Ok(stdout)
    }

    /// Issue the given command and return the command's standard output.
    pub fn cmd(&self, cmd: &str) -> Result<String, Error> {
        Ok(String::from_utf8(self.cmd_raw(cmd)?)?)
    }

    /// Copy a file from the local machine to the remote host.
    ///
    /// Both remote and local paths can be absolute or relative.
    ///
    /// ```rust,no_run
    /// # use tsunami::Session;
    /// # use failure::Error;
    /// # fn upload_artifact(ssh: Session) -> Result<(), Error> {
    ///     use std::path::Path;
    ///     ssh.upload(
    ///         Path::new("build/output.tar.gz"), // on the local machine
    ///         Path::new("/srv/output.tar.gz"), // on the remote machine
    ///     )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn upload(&self, local_src: &Path, remote_dst: &Path) -> Result<(), Error> {
        let sftp = self.ssh.sftp().map_err(Error::from).map_err(|e| {
            e.context(format!(
                "failed to create ssh channel while uploading file '{}'",
                local_src.display()
            ))
        })?;
        let mut dst_file = sftp.create(&remote_dst).map_err(Error::from).map_err(|e| {
            e.context(format!(
                "failed to create file '{}' on remote host",
                remote_dst.display()
            ))
        })?;

        let mut src_file = File::open(&local_src).map_err(Error::from).map_err(|e| {
            e.context(format!(
                "failed to open file '{}' on local machine",
                local_src.display()
            ))
        })?;

        let copied = io::copy(&mut src_file, &mut dst_file)
            .map_err(Error::from)
            .map_err(|e| {
                e.context(format!(
                    "failed to upload file '{}' to remote host",
                    local_src.display()
                ))
            })?;

        let expected = src_file.metadata()?.len();
        if copied < expected {
            Err(FileTransferFailure {
                file: local_src.display().to_string(),
                msg: format!("only copied {}/{} bytes", copied, expected),
            })?
        }

        Ok(())
    }

    /// Copy a file from the remote host to the local machine.
    ///
    /// Both remote and local paths can be absolute or relative.
    ///
    /// ```rust,no_run
    /// # use tsunami::Session;
    /// # use failure::Error;
    /// # fn download_hostname(ssh: Session) -> Result<(), Error> {
    ///     use std::path::Path;
    ///     ssh.download(
    ///         Path::new("/etc/hostname"), // on the remote machine
    ///         Path::new("remote-hostname"), // on the local machine
    ///     )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn download(&self, remote_src: &Path, local_dst: &Path) -> Result<(), Error> {
        let sftp = self.ssh.sftp().map_err(Error::from).map_err(|e| {
            e.context(format!(
                "failed to create ssh channel while downloading file '{}'",
                remote_src.display()
            ))
        })?;
        let mut src_file = sftp.open(&remote_src).map_err(Error::from).map_err(|e| {
            e.context(format!(
                "failed to open file '{}' on remote host",
                remote_src.display()
            ))
        })?;

        let mut dst_file = File::create(&local_dst).map_err(Error::from).map_err(|e| {
            e.context(format!(
                "failed to create file '{}' on local machine",
                local_dst.display()
            ))
        })?;

        let copied = io::copy(&mut src_file, &mut dst_file)
            .map_err(Error::from)
            .map_err(|e| {
                e.context(format!(
                    "failed to download file '{}' from remote host",
                    remote_src.display()
                ))
            })?;

        // `stat().size` can be None. A little odd but not worth failing if
        // everything else seemed to succeed.
        if let Some(expected) = src_file.stat()?.size {
            if copied < expected {
                Err(FileTransferFailure {
                    file: remote_src.display().to_string(),
                    msg: format!("only copied {}/{} bytes", copied, expected),
                })?
            }
        }

        Ok(())
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
