# Baby Reversing Level 13
This one is getting a little bit more complex but still the same concept as the last XOR challenges, in this challenge we need to input a 29 bytes string, and each bytes get XOR with the following key **0xcd1167**.

Let's write the solving script for this challenge :
```py
def xor_unmangler(val, key):
    i = 0
    res = []

    for j in val:
        if i > 2:
            i = 0
        res.append(j ^ key[i])
        i+=1
    
    return res

l =[172, 112, 6, 174, 114, 3, 165, 120, 14, 166, 124, 8, 162, 97, 23, 189, 97, 19, 185, 100, 17, 186, 102, 16, 181, 105, 30, 180, 107]
res = xor_unmangler(l, [0xcd, 0x11, 0x67])
print("".join([bytes.fromhex(str(hex(i)[2:])).decode() for i in res]))
```