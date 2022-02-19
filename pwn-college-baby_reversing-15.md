# Baby Reversing Level 15
Wow, this challenge was absolutely awesome to do, in this one you will need to combine all the knowledge you've obtained so far in the latest challenges to retrieve the expected value, for this we will write a python script, it will be bigger than the last one but it will give you a better understanding of each mangling operations.

```py
#!/usr/bin/env python3

expected_value = [0xd7, 0x9b, 0x9b, 0x39, 0xc3, 0x4a, 0xe0, 0x56, 0x8a, 0xed, 0xbc, 0x30, 0xdb, 0xb5, 0x90, 0xe7, 0xb1, 0x8e, 0xbe, 0x96, 0xab, 0xe4, 0xa3, 0x5a, 0x06, 0xfc, 0x80, 0xd3, 0xab, 0x41, 0xda, 0x43, 0xe2, 0xf5, 0x97, 0x42, 0xca, 0x96, 0x5c]

def sort_mangler(val):
    return sorted(val)

def xor_mangler(val, key):
        res = []
        for i in val:
            res.append(i ^ key)

        return res

def nxor_mangler(val, key):
        i = 0
        res = []
        for j in val:
            if i > len(key) - 1:
                i = 0
            res.append(j ^ key[i])
            i+=1
        return res

def swap_index(val, index_1, index_2):
    temp = val[index_1]
    val[index_1] = val[index_2]
    val[index_2] = temp
    return val

def decode_final_string(val):
    return "".join([bytes.fromhex(str(hex(i)[2:])).decode() for i in val])


def decode_value():
    value = []
    # First mangling is a XOR with 0x42
    value = xor_mangler(expected_value, 0x42)
    
    # Second mangling is a Multiple XOR with 0x7e372d5c1cf3
    value = nxor_mangler(value, [0x7e, 0x37, 0x2d, 0x5c, 0x1c, 0xf3])

    # Third mangling is a swap of index with 27 and 34
    value = swap_index(value, 27, 34)
    
    # Fourth mangling is a swap of index with 7 and 10
    value = swap_index(value, 7, 10)

    # Fifth mangling is a reverse
    value.reverse()         # The reverse function doesn't return anything, instead it update the current list.

    # Six'th mangling is a XOR with the key 0x52829491af88ee
    value = nxor_mangler(value, [0x52, 0x82, 0x94, 0x91, 0xaf, 0x88, 0xee])

    # Seven'th and last mangling is a sort
    value.sort()            # The sort function doesn't return anything, instead it update the current list.

    # Print final list of value as a string
    print(decode_final_string(value))


if __name__ == "__main__":
    decode_value()
```

Running the script should output the right value the program expects us to input.