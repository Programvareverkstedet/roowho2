# roowhoo2

Reimplementation of a subset of linux' netkit tools.

## Programs reimplemented

- [ ] finger
- [ ] rup
- [ ] ruptime
- [ ] rusers
- [ ] rwall
- [ ] rwho

## Programs *not* reimplemented

- `rsh`/`rexec`/`rcp`/`rlogin`: use `ssh` + `scp`/`rsync`
- `talk`: use a local irc server
- `ping`/`telnet`/`ftp`/`tftp`/`write`: all of these you can get from other packages
- `inetd`: either use a different distribution or use systemd socket activation
- `timed`: use an ntp client
- `biff`/`comsat`: nah
- `ripquery`/`routed`: nuh-uh
- `rpc*`: no need
