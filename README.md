# tsunami

[![Crates.io](https://img.shields.io/crates/v/tsunami.svg)](https://crates.io/crates/tsunami)
[![Documentation](https://docs.rs/tsunami/badge.svg)](https://docs.rs/tsunami/)
[![Build Status](https://travis-ci.org/jonhoo/tsunami.svg?branch=master)](https://travis-ci.org/jonhoo/tsunami)

`tsunami` provides an interface for running short-lived jobs and experiments on EC2 spot block
instances. Most interaction with this library happens through
[`TsunamiBuilder`](struct.TsunamiBuilder.html).

## Examples

```rust
let mut b = TsunamiBuilder::default();
b.use_term_logger();
b.add_set(
    "server",
    1,
    MachineSetup::new("m5.large", "ami-e18aa89b", |ssh| {
        ssh.cmd("yum install nginx").map(|out| {
            println!("{}", out);
        })
    }),
);
b.add_set(
    "client",
    3,
    MachineSetup::new("m5.large", "ami-e18aa89b", |ssh| {
        ssh.cmd("yum install wget").map(|out| {
            println!("{}", out);
        })
    }),
);

b.run(|vms: HashMap<String, Vec<Machine>>| {
    println!("==> {}", vms["server"][0].private_ip);
    for c in &vms["client"] {
        println!(" -> {}", c.private_ip);
    }
    // ...
    Ok(())
}).unwrap();
```

## Live-coding

The crate is under development as part of a live-coding stream series intended for users who
are already somewhat familiar with Rust, and who want to see something larger and more involved
be built.

You can find the recordings of past sessions below:
- [Part 1](https://youtu.be/Zdudg5TV9i4)
- [Part 2](https://youtu.be/66INYb73yXo)
