# Windows Cheatsheet
Since i am more of the Linux type than Windows (for now), i will make this small cheatsheet where i will add, tips and tricks troughout time.

Note that those are a bit like personal notes but if you find something that should be changed or something that need to be added, feel free to reach out to me.

## Export wireless profiles with passwords
Exporting wireless profiles on Windows is something pretty simple to do, you can achieve this using the following command.
```
$ netsh wlan export profile key=clear
```
This will export each network the computer recently connected to along with the passwords for these networks in a XML file.

You could write a script to export these files, either using a request, dns exfil, email, or anything that comes through your mind.

## Bypassing Antivirus with DumpStack.log trick
Windows Defender is a little weird sometimes, in fact you can bypass it just by naming your file DumpStack.log, this work since Windows does not scan files named DumpStack.log. This will probably be patched in the future but it can be useful on unpatched computes.

![Mimikatz bypass Defender](https://i.imgur.com/RnAUQEn.png)
