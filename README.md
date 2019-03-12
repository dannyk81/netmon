# netmon

This is a quick hack to allow tracing Netlink events, our main goal was to trace the PID (PortID) of Route Add/Delete events.

This was inspired by code from `iproute2` and Oleg Kutkov's awesome blog and examples: http://olegkutkov.me/2018/02/14/monitoring-linux-networking-state-using-netlink/

# build

Clone the repo and compile with gcc
```
$ gcc netmon.c -o netmon
```
