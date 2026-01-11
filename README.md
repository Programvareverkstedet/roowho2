[![Coverage](https://pages.pvv.ntnu.no/Projects/roowho2/main/coverage/badges/for_the_badge.svg)](https://pages.pvv.ntnu.no/Projects/roowho2/main/coverage/)
[![Docs](https://img.shields.io/badge/rust_docs-blue?style=for-the-badge&logo=rust)](https://pages.pvv.ntnu.no/Projects/roowho2/main/docs/roowho2_lib/)

# roowhoo2

Reimplementation of a subset of linux' netkit tools.

## Programs reimplemented

- [ ] finger
- [X] rwho/ruptime
- [ ] rusers/rup
- [ ] rwall

## Programs *not* reimplemented

- `rsh`/`rexec`/`rcp`/`rlogin`: use `ssh` + `scp`/`rsync`
- `talk`: use a local irc server
- `ping`/`telnet`/`ftp`/`tftp`/`write`: all of these you can get from other packages
- `inetd`: either use a different distribution or use systemd socket activation
- `timed`: use an ntp client
- `biff`/`comsat`: nah
- `ripquery`/`routed`: nuh-uh
- `rpc*`: no need

## Development

> [!NOTE]
> We have created some nix code to generate a QEMU VM with a setup similar to a production deployment
> There is not necessarily any VMs running in a production setup, and if so then at least not this VM.
> It is mainly there for easy access to interactive testing, as well as for testing the NixOS module.

You can easily start developing this with nix, by running the test VM:

```bash
nix run .#vm
```

You can also build the nix package, or run the executable directly:

```bash
# Build package
nix build .#

# Run the executable (after building package)
nix run .#
```

Within the VM, you will find several NixOS containers configured behind NAT with the container host, all running `roowhod`.
These containers and the container host (the VM itself) will broadcast rwhod content between them in order to simulate a LAN
with several machines connected. You can enter the different containers like this:

```bash
machinectl shell c1
# Press 'Ctrl + ]' 3 times rapidly in a row to exit
machinectl shell c2
```

<small>This product includes software developed by the University of California, Berkeley and its contributors.</small>
