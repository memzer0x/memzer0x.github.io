# Flare-On 2021 - Known
Known is the second challenge of the annual Flare-On (2021) reverse engineering event, the challenge was pretty original and i thought it might be a good idea to make a writeup on how i was able to solve this challenge.

This writeups is being post a LOT lately since i was pretty busy when the Flare-On 2021 CTF event occured, so here i am a couple of months later doing the challenges.

## Static Analysis
First step in any good reverse engineering process is **static analysis** of the binary, so without hesitating let's get to it, we will use the following binaries to achieve this.

### CFF Explorer
CFF Explorer might be one of the best tools when it comes to static analysis of PE Binaries (Windows Binaries basically). 

![PE Informations](https://i.imgur.com/PDS4Few.png)

Looking at the results after dropping the executable in CFF Explorer, we can notice that it's a 32bit binary.

Looking at the import directory shows that only KERNEL32.dll is imported by our executable.
![](https://i.imgur.com/zYXMRIk.png)

And it imports the following functions from KERNEL32.dll, functions like *SetCurrentDirectory, FindFirstFileA, FindNextFileA, CreateFileA, WriteFile and ReadFile*, tells us that the executable works a lot with files and is probably looping through some files. 
![](https://i.imgur.com/jt4iRWF.png)

Without even having to run the binary we already obtain a LOT of knowledge on how this program will work, let's try to run it in order to see what this program is doing.

*Note, when we're running an unkown file that rely heavily on file operations it is kind of suspicious, best bet would be to run these kind of binaries in a virtual environment.*

## Running the Executable
It's time to finally execute this binary, this should give us a lot more knowledge than we already have on how this program works.
![](https://i.imgur.com/8qcob8H.png)

Upon double clicking on the executable a console opens with a *Ransomware-Like* message telling us that our files were encrypted with a "strong algorithm" (we'll see that).

Decoding the Base64 encoded string reveals us some hint on the challenge even though i feel like unecessary because we'll be able to figure this out on our own, lets still decode.
![](https://i.imgur.com/ukgNcIE.png)

Apparently the "strong algorithm" seems to be only some add and rotate bitwise manipulations.

The binary is waiting for us to input a `decryption key` and it will be used to decrypt the flag stored in one of the files in our `Files` folder that comes with the challenge.

Out of curiosity i wanted to see how much input the program is trying to read from us, so i dropped into IDA real quick and as you can see there is high amount of chances that the decryption key is only 8 bytes.

![](https://i.imgur.com/18Bzc04.png)

## Reversing the Binary
Opening the binary in IDA which you probably already done, shows that the function where "everything begins" is at address `0x00EC1460`, this function is responsible for showing the console, printing the text on it and ask us for input.

3 instructions later we have a call to another function at address `0x00EC1370`, looking at the content of this function i concluded that this function is responsible for all the logic behind the program, so i renamed the function `main_logic`.

Looking at the content of the `main_logic` i concluded that this function is looping through each one of these files, and decrypts all `.encrypted` files in new files without the `.encrypted` suffix.

Looking at the files inside our `Files` directory, i noticed a file named `latin_alphabet.txt.encrypted`, which as the name suggests contains an encrypted version of the latin alphabet (A-Z) (26 characters), the fact that the file is 26 bytes long also highly suggest that too.

Knowing the content of the `latin_alphabet.txt.encrypted` file even if encrypted will be HIGHLY helpful when writing our key "bruteforcing" algorithm.

Next step would be to find the function where all the decryption logic happens, looking through the function we can see that the decryption function starts at address `0x00EC1220`, i took the care to rename the function `potentially_decryption_routine` instead of `loc_EC1220`.
![](https://i.imgur.com/jRcn32S.png)

In the preceding screenshot you can see 2 calls to `CreateFileA`, the first one is responsible for opening a file handle on our already existing `.encrypted` file and the second one is responsible for creating a new file this time without the `.encrypted` suffix and open a HANDLE on this new file.

So we know that each time we loop into a new file, this `potentially_decryption_routine` function gets called.

We can therefore put a breakpoint at address `0x00EC13BE` this way we can know which file we are dealing with before continuing.
![](https://i.imgur.com/v3oqbmX.png)

Then you can start the program, enter a random 8 bytes (or characters if you prefer) decryption key, then we should eventually hit the breakpoint.

Now your gonna want to click the IDA continue green button on top of the debugging interface, until this `ebp+FindFileData.cFileName` is equal to `latin_alphabet.txt.encrypted`.

After doing all this you can **step inside**, the `potentially_decryption_routine` function.

After the 2 calls to `CreateFileA` we just saw, the program reads 8 bytes into the **encrypted content** as you can see in the following picture.
![](https://i.imgur.com/egqP1D2.png)

Then the program eventually enters the real decryption routine, which should be at address `0x00EC11F0`, we can rename the function `loc_EC11F0` to `DECRYPTION_MANGLING`.

Looking at the `DECRYPTION_MANGLING` function we can see that it's nothing really scary, we loop `8` times for those `8 bytes`, and each time we do the following.
- XOR the `value[current_loop_it]` with the `key[current_loop_it]`
- Rotate left `value`, the amount of `current_loop_it`
- Substract value with `current_loop_it`

![](https://i.imgur.com/R05EDeB.png)

And then we write the result in the `latin_alphabet.txt` file, which with the right key should output us the decrypted content of `the latin_alphabet.txt.encrypted`.

We can easily reverse the decryption key using the algorithm used by the decryption routine, all this can be done since we know the content of the first 8 bytes of the latin alphabet file.

## Write the Bruteforce Script
Now it's time to get our hands dirty and reverse this decryption key, for this nothing better than a python script !

You might expect the script to be super big but nope, it took 2 bitwise lambdas and a for loop, then we can solve this challenge.

Since we know the steps of the algorithm for decrypting the file we can try to reverse the order of these steps to obtain the decryption key.

```py
encrypted_content = bytearray(b'\x0f\xce\x60\xbc\xe6\x2f\x46\xea')
org = bytearray(b'ABCDEFGH')

# Bitwise Add Operation
add_op = lambda b, i: (b+i) % 256	# Modulo with 256 since we're interested only in the last 8 bits of the value (2**8 == 256)

# Bitwise Rotate Operation
ror_op = lambda b, i: (b>>i)|((b<<(8-i)) & 255)

# Recover the decryption key
for i in range(0, 8):
	org[i] = ror_op(add_op(org[i], i), i) ^ enc[i]

# Print the decryption key recovered
print(org)

```

Running this script outputs us the key `No1Trust` ! Time to try and decrypt these damn files :)

## Solving the Challenge
Easiest part and also the most rewarding, it's time to test if everything works as expected. Let's run our binary and put No1Trust as the decryption key.

Looking at the files after this run we can see that each one of em are decrypted, let's check the content of the `critical_data.txt` file.

![](https://i.imgur.com/3ftcKOh.png)

And it's a FLAG !

I hope you enjoyed the challenge as much as i enjoyed doing it, even though i did it later than supposed i'm pretty happy with it.
