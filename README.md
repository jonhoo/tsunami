# tsunami

[![Crates.io](https://img.shields.io/crates/v/tsunami.svg)](https://crates.io/crates/tsunami)
[![Documentation](https://docs.rs/tsunami/badge.svg)](https://docs.rs/tsunami/)
[![Build Status](https://travis-ci.org/jonhoo/tsunami.svg?branch=master)](https://travis-ci.org/jonhoo/tsunami)

`tsunami` provides an interface for running short-lived jobs and experiments on cloud
instances. Most interaction with this library happens through
[`TsunamiBuilder`](struct.TsunamiBuilder.html) and [`Tsunami`](struct.Tsunami.html).

# Example

```rust,no-run
fn main() -> Result<(), failure::Error> {
    use tsunami::providers::aws;
    let mut aws = TsunamiBuilder::<aws::AWSRegion>::default();
    let m = aws::MachineSetup::default();
    aws.add("my_vm".into(), m);
    let tsunami = aws.spawn()?;
    let vms = tsunami.get_machines()?;
    let my_vm = vms.get("my_vm").unwrap();
    let ssh = my_vm.ssh.as_ref().unwrap();
    ssh.cmd("hostname").map(|(stdout, _)| println!("{}", stdout))?;
}
```

# Live-coding

An earlier version of this crate was written as part of a live-coding stream series intended for users who
are already somewhat familiar with Rust, and who want to see something larger and more involved
be built. You can find the recordings of past sessions [on
YouTube](https://www.youtube.com/playlist?list=PLqbS7AVVErFgY2faCIYjJZv_RluGkTlKt).
