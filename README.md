# tsunami

[![Crates.io](https://img.shields.io/crates/v/tsunami.svg)](https://crates.io/crates/tsunami)
[![Documentation](https://docs.rs/tsunami/badge.svg)](https://docs.rs/tsunami/)
[![Build Status](https://travis-ci.org/jonhoo/tsunami.svg?branch=master)](https://travis-ci.org/jonhoo/tsunami)

`tsunami` provides an interface for running short-lived jobs and experiments on cloud
instances. Most interaction with this library happens through
[`TsunamiBuilder`](struct.TsunamiBuilder.html) and [`Tsunami`](struct.Tsunami.html).

# Example

```rust,no-run
use tsunami::providers::{aws, Launcher};
use tsunami::TsunamiBuilder;
fn main() -> Result<(), failure::Error> {
    let mut b = TsunamiBuilder::default();
    b.add("my machine", aws::Setup::default()).unwrap();
    let mut l = aws::Launcher::default();
    b.spawn(&mut l).unwrap();
    let vms = l.connect_all().unwrap();
    let my_machine = vms.get("my machine").unwrap();
    let (stdout, stderr) = my_machine.ssh.as_ref().unwrap().cmd("echo \"Hello, EC2\"").unwrap();
    println!("{}", stdout);
}
```

# Live-coding

An earlier version of this crate was written as part of a live-coding stream series intended for users who
are already somewhat familiar with Rust, and who want to see something larger and more involved
be built. You can find the recordings of past sessions [on
YouTube](https://www.youtube.com/playlist?list=PLqbS7AVVErFgY2faCIYjJZv_RluGkTlKt).
