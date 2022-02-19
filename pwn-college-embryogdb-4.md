# EmbryoGDB Level 4
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
**Task** : There are a number of ways to move forward in the program's execution. You can use the `stepi <n>` command, or `si <n>` for short, in order to step forward one instruction. You can use the `nexti <n>` command, or `ni <n>` for short, in order to step forward one instruction, while stepping over any function calls. The `<n>` parameter is optional, but allows you to perform multiple steps at once. You can use the `finish` command in order to finish the currently executing function. You can use the `break *<address>` parameterized command in order to set a breakpoint at the specified-address. You have already used the `continue` command, which will continue execution until the program hits a breakpoint.

While stepping through a program, you may find it useful to have some values displayed to you at all times. There are multiple ways to do this. The simplest way is to use the `display/<n><u><f>` parameterized command, which follows exactly the same format as the `x/<n><u><f>` parameterized command. For example, `display/8i $rip` will always show you the next 8 instructions. On the other hand, `display/4gx $rsp` will always show you the first 4 values on the stack. Another option is to use the `layout regs` command. This will put gdb into its TUI mode and show you the contents of all of the registers, as well as nearby instructions.

In order to solve this level, you must figure out a series of random values which will be placed on the stack. You are highly encouraged to try using combinations of `stepi`, `nexti`, `break`, `continue`, and `finish` to make sure you have a good internal understanding of these commands. The commands are all absolutely critical to navigating a program's execution.

You can solve the challenge using the following commands :
```
gdb> disass main
   .................. .......   ...    ...............
   .................. .......   ...    ...............
   .................. .......   ...    ...............
   0x0000555555555c80 <+474>:   mov    esi,0x0
   0x0000555555555c85 <+479>:   lea    rdi,[rip+0xe3c]        # 0x555555556ac8
   0x0000555555555c8c <+486>:   mov    eax,0x0
   0x0000555555555c91 <+491>:   call   0x555555555250 <open@plt>
   0x0000555555555c96 <+496>:   mov    ecx,eax
   0x0000555555555c98 <+498>:   lea    rax,[rbp-0x18]
   0x0000555555555c9c <+502>:   mov    edx,0x8
   0x0000555555555ca1 <+507>:   mov    rsi,rax
   0x0000555555555ca4 <+510>:   mov    edi,ecx
   0x0000555555555ca6 <+512>:   call   0x555555555210 <read@plt>

gdb> b *main+512
Breakpoint 1 at 0x0000555555555ca6

gdb> c
Continuing.

gdb> ni
gdb> x/gx $rbp-0x18
0x7fffffffdd38: 0x6ce885632f7847a9

gdb> c
Random value: 6ce885632f7847a9
You input: 6ce885632f7847a9
The correct answer is: 6ce885632f7847a9

gdb> c
gdb> ni
gdb> x/gx $rbp-0x18
0x7fffffffdd38: 0xa21985366881490f

gdb> c
Random value: a21985366881490f
You input: a21985366881490f
The correct answer is: a21985366881490f

gdb> c
gdb> ni
gdb> x/gx $rbp-0x18
0x7fffffffdd38: 0x1062cc677e90758c

gdb> c
Random value: 1062cc677e90758c
You input: 1062cc677e90758c
The correct answer is: 1062cc677e90758c
You win! Here is your flag:
pwn.college{REDACTED}
```