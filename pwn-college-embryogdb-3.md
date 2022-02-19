# EmbryoGDB Level 3
Every Single challenges of the embryogdb suit of challenges can be completed using the following gdb commands.

```
gdb> call (void)win()
pwn.college{REDACTED}

or

gdb> info functions win
Non-debugging symbols:
0x000055e66e4f0a86  main

gdb> set $rip=0x000055e66e4f0a86
gdb> c
pwn.college{REDACTED}
```

## Right way to solve the challenge
**Task** : You can examine the contents of memory using the `x/<n><u><f> <address>`. In this format `<u>` is the unit size to display, `<f>` is the format to display it in, and `<n>` is the number of elements to display. Valid unit sizes are `b` (1 byte), `h` (2 bytes), `w` (4 bytes), and `g` (8 bytes). Valid formats are `d` (decimal), `x` (hexadecimal), `s` (string), `i` (instruction). The address can be specified using a register name, symbol name, or absolute address. Additionally, you can supply mathematical expressions when specifying the address.

For  example, `x/8i $rip` will print the next 8 instructions from the current instruction pointer. `x/16i main` will print the first 16 instructions of the main function. You can also use `disassemble main`, or `disas main` for short, to print all of the instructions of main. Alternatively, `x/16gx $rsp` will print the first 16 values on the stack. `x/gx $rbp-0x32` will print the local variable stored there on the stack.

You will probably want to view your instructions using the CORRECT assembly syntax. You can do that with the command `set disassembly-flavor intel`.

In order to solve this level, you must figure out the random value on the stack (the value read in from `/dev/urandom`). Think about what the arguments to the read system call are.

You can solve the challenge using the following commands :
```
gdb> disass main
   .................. .......   ...    ...............
   .................. .......   ...    ...............
   .................. .......   ...    ...............
   0x000056488bdccc31 <+395>:   lea    rdi,[rip+0xbd5]        # 0x56488bdcd80d <"/dev/urandom">
   0x000056488bdccc38 <+402>:   mov    eax,0x0
   0x000056488bdccc3d <+407>:   call   0x56488bdcc250 <open@plt> # call to open
   0x000056488bdccc42 <+412>:   mov    ecx,eax
   0x000056488bdccc44 <+414>:   lea    rax,[rbp-0x18]		# buffer we will read in
   0x000056488bdccc48 <+418>:   mov    edx,0x8
   0x000056488bdccc4d <+423>:   mov    rsi,rax
   0x000056488bdccc50 <+426>:   mov    edi,ecx
   0x000056488bdccc52 <+428>:   call   0x56488bdcc210 <read@plt> # call to read

gdb> x/gx $rbp-0x18
0x7ffc2ab310e8: 0x6ce885632f7847a9

gdb> c
Continuing.
Random value: 6ce885632f7847a9
You input: 6ce885632f7847a9
The correct answer is: 6ce885632f7847a9
You win! Here is your flag:
pwn.college{REDACTED}
```