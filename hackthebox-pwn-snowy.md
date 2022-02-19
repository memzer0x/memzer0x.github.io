# Cyber Santa is Coming to Town (Pwn Mr.Snowy)
So this was the first pwn challenge of the hackthebox 2021 christmas hacking ctf, it was **too much simple** i think but was a great practice whatsoever.

## Solving the Challenge
The program starts by telling us, we are in Santa's garden, and there is a suspicious snowman.
We are then asked between 2 choices :
   
    - Investigate
    - Let it be

If you choose Let it be, the program will just quit without doing anything, however if you use the Investigate button the program will use the **read** syscall to **read 0x108 bytes inside a buffer of 64 bytes**, this is a regular buffer overflow, next step was to find the offset at which we can overwrite the return address of the current function we're in. 

For this i have sent a **cyclic pattern of 500 bytes** to our program, running it in gdb shows us that the return address starts to be overwritten after 72 bytes, this means we need an offset of **72 bytes before our shellcode or whatever exploit we will use**.

After looking at what i can now do, i found this function called **deactivate_camera**, the body of the functions lookslike it reads a flag file and output it to stdout.

Changing the return address for the **deactivate_camera** function effectively reads the flag, we can now write a python script to automatically solve this challenge :
```py
import pwn

pwn.context.arch = "amd64"

elf = ELF("/challenge/pwn_mr_snowy/mr_snowy")
io = elf.process()

win_function_addr = elf.sym["deactivate_camera"]

payload = b"A" * 72 + p64(win_function_addr) 

io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"> ", payload)
io.interactive()
```

This code should return inside the **deactivate_camera** function and therefore print your flag :)
