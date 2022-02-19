# Baby Reversing Level 10
I'm making a writeup on this one cause i was able to make a cool little one liner to solve this challenge.

```py
>>> l = [170, 184, 168, 175, 191]
>>> "".join([bytes.fromhex(str(hex(i ^ 4294967259)[8:])).decode() for i in l])
'qcstd'
```

Inputting `qcstd` to the program outputs us the flag.

