# Joining IRC Server through tor
So this tutorial is for the newbies out here that ask me how they can anonymously join IRC servers without leaking your IP Address or personal information about you. If set up properly, IRC can be one of the most secured way of sending messages out here just make sure your IRC server is using SSL protection or else your message won't be encrypted when sent, another good alternative could potentially be [wire](https://app.wire.com).

## Installing Requirements
The way we will be using requires a couple of requirements so we can join properly. First we will need to install these requirements, which will be used to connect to IRC servers anonymously.

On Debian based systems :
```
$ sudo apt-get update && sudo apt-get upgrade
$ sudo apt-get install tor socat irssi
```

On Arch Linux :
```
$ sudo pacman -Syu tor socat irssi
```

## Connecting to a IRC Server
As an example we will connect to my IRC server at irc.reversing-ninja.com, but we will join through the onion address instead at ninjawafrnb67wn66umufhjwaddmcklk2tn2a7t2cok2pl43jjzkvead.onion.

The following command will start a listener on port 4229 and redirect the data received to the address ninjawafrnb67wn66umufhjwaddmcklk2tn2a7t2cok2pl43jjzkvead.onion:6697 using socksport 9050, which is the port on which tor runs by default.
```
$ socat TCP4-LISTEN:4229,fork
SOCKS4A:localhost:ninjawafrnb67wn66umufhjwaddmcklk2tn2a7t2cok2pl43jjzkvead.onion:6697,socksport=9050
```

Before attempting to connect, always make sure tor is running first, for this use the following command.
```
$ sudo systemctl start tor
```

Then the final step, you can start irssi and log in to the server.
```
$ irssi
>> /connect -ssl localhost 4229
```

:)
