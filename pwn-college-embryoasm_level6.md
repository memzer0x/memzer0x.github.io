# EmbryoASM Level 6
So this challenge is a little bit harder since we need to compute the modulo of rdi with 256 and rsi with 65536 using only
MOV instructions.

Since i am nowhere near being a shifting, rotating and masking or mathematic wizard, i was struggling at the beginning of this challenge. But thanks to Kanak on discord, he showed us on video a little more how we were supposed to complete the challenge and everything start making sense for me.

## How it works
Basically the program asks us to modulo with 256 and 65536, note that :
   
    - 4 is the biggest value 2 bits can address.
    - 16 is the biggest value 4 bits can address.
    - 256 is the biggest value 8 bits can address.
    - 65536 is the biggest value 16 bits can address.

When we talk about modulo, we always think about division and the remainder of it.

But there's something special about modulo with 4, 16, 256, 65536,... :
    
    - When we do modulo with 4 we're basically asking for the last 2 bits of that number (Square root of 4).
    - When we do modulo with 16 we're basically asking for the last 4 bits of that number (Square root of 16).
    - When we do modulo with 256 we're basically asking for only the last 8 bits of that number (Square root of 256).
    - When we modulo with 65536 we're basically asking for only the last 16 bits of that number (Square root of 65536).

Examples:
```
   9382 % 4 = 2         <= Here we access the last 2 bits
   9382 % 16 = 6       <= Here we access the last 4 bits
   9382 % 256 = 166     <= Here we access the last 8 bits
   9382 % 65536 = 9382  <= Here we access the last 16 bits
```

```
  2019249 % 4 = 1        <= Here we access the last 2 bits
  2019249 % 16 = 1      <= Here we access the last 4 bits
  2019249 % 256 = 177    <= Here we access the last 8 bits
  2019249 % 65536 = 53169 <= Here we access the last 16 bits
```

```
  0x12345678 % 4 = 0
  0x12345678 % 16 = 0x8
  0x12345678 % 256 = 0x78
  0x12345678 % 65536 = 0x5678
  0x12345678 % 4294967296 = 0x12345678

  It is sometimes easier to see the pattern using hexadecimal characters.
```

But since we can't use division on the challenge we need to know how to compute modulo a different way...

After a bit of research i stumbled across this post on stackoverflow where someone was asking different ways to modulo a certain value, i read that these operations are the same :
```
    9382 % 4 = 2
    9382 & (4 - 1) = 2        <= Same as the precedent operation

    9382 % 16 = 6
    9382 & (16 - 1) = 6       <= Same as the precedent operation

    9382 % 256 = 166
    9382 & (256 - 1) = 166    <= Same as the precedent operation

    9382 % 65536 = 9382
    9382 & (65536 - 1) = 9382 <= Same as the precedent operation
```

```
    0x12345678 % 16 = 0x8
    0x12345678 & (16 - 1) = 0x8

    0x12345678 % 256 = 0x78
    0x12345678 & (256 - 1) = 0x78
    
    0x12345678 % 65536 = 0x5678
    0x12345678 & (65536 - 1) = 0x5678

    0x12345678 % 4294967296 = 0x12345678
    0x12345678 & (4294967296 - 1) = 0x12345678
```

What we're doing is basically *masking* a number by **AND'ing** with (2 ** n bits we want to access - 1) and this does the same result as doing modulo on (2 ** n bits we want to access).

Let's put this in practice and complete the challenge

## Solving the Challenge
Okay so completing the challenge was pretty simple, we are asked to do the following :
```
Welcome to EmbryoASMLevel6
==================================================
To interact with any level you will send raw bytes over stdin to this program.
To efficiently solve these problems, first run it once to see what you need,
then craft, assemble, and pipe your bytes to this program.

In this level you will be working with registers. You will be asked to modify
or read from registers_use.

We will now set some values in memory dynamically before each run. On each run
the values will change. This means you will need to do some type of formulaic
operation with registers_use. We will tell you which registers_use are set beforehand
and where you should put the result. In most cases, its rax.

Another cool concept in x86 is the independent access to lower register bytes.
Each register in x86 is 64 bits in size, in the previous levels we have accessed
the full register using rax, rdi or rsi. We can also access the lower bytes of
each register using different register names. For example the lower
32 bits of rax can be accessed using eax, lower 16 bits using ax,
lower 8 bits using al, etc.
MSB                                    LSB
+----------------------------------------+
|                   rax                  |
+--------------------+-------------------+
                     |        eax        |
                     +---------+---------+
                               |   ax    |
                               +----+----+
                               | ah | al |
                               +----+----+
Lower register bytes access is applicable to all registers_use.

Using only the following instruction(s):
mov
Please compute the following:
rax = rdi modulo 256
rbx = rsi module 65536

We will now set the following in preparation for your code:
rdi = 0x57c5
rsi = 0x4fe709fc


Please give me your assembly in bytes (up to 0x1000 bytes):
```

Note that on x64 you can access the lower 8 bits of rsi and rdi, using sil and dil, respectively. 

This mean we can complete this challenge using only the mov instruction as asked.

```x86asm
.global _start
.intel_syntax noprefix
_start:
    mov rax, 0      ; zero out rax
    mov al, dil     ; take the last 8 bits of rdi into last 8 bits of rax
    mov rbx, 0      ; zero out rbx
    mov bx, si      ; take the last 16 bits of rsi into last 16 bits of rbx
```
