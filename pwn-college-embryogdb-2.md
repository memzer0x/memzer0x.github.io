# EmbryoGDB Level 2
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
**Task** : You can see values for all your registers with `info registers`. Alternatively, you can also just print a particular register's value with the `print` command, or `p` for short. For example, `p $rdi` will print the value of $rdi in decimal. You can also print it's value in hex with `p/x $rdi`.

In order to solve this level, you must figure out the current random value of register r12 in hex.

You can solve the challenge using the following commands :
```
gdb> p/x $r12
$4 = 0xdf95a693d3e597cb

gdb> r
Continuing.
Random value: df95a693d3e597cb
Your input: df95a693d3e597cb
The correct answer is: df95a693d3e597cb
You win! Here is your flag:
pwn.college{REDACTED}

```