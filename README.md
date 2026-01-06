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
