# Scan Ports faster than most using masscan
nmap might be the greatest tool for deep and detailed port scanning, however it's pretty slow, and when you are hacking in competition you usually need to be fast.

So here comes masscan, this tool will scan every ports available on a machine (TCP/UDP) and do this 5-10x faster than a full nmap scan would, however note that nmap scans tends to give much more information that masscan.
```bash
$ masscan -p1-65535,U:1-65535 --rate=1000 -e tun0
```
The preceeding command will scan for UDP and TCP ports on port 1 to 65535 with a rate of 1000 packets per second and all this will be done on the adapter named tun0.

I always like to specify the adapter name, just in case masscan decide to start the scan inside the wrong network.
