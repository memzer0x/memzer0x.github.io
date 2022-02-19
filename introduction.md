# Binary Exploitation and Reverse Engineering

**First things first, welcome in my gitbook !**

I decided to make a mdbook so i can share writeups and exploits i found throughout time more easily online...

Hopefully you will enjoy it as much as i did enjoy making the page :)

**Time for Explanations !**  Let's start with what is Reverse Engineering

# What is Reverse Engineering ?

To get a good definition of what is really Reverse Engineering i wen't on Wikipedia... Yeah i know pretty lame.

**Reverse engineering** (also known as backwards engineering or back engineering) is a process or method through the application of which one attempts to **understand through deductive reasoning how a device, process, system, or piece of software accomplishes a task with very little (if any) insight into exactly how it does so.**

In our case, we're **Reverse Engineering programs (Binary Executables)**, to do that we're using **Decompilers, Debuggers, Disas, Hex Editors, PE Structure Analysis Tools and many more...** note that you can reverse pretty much anything that has been engineered in the first place.
	
![alt](https://c.tenor.com/K8R7LThju04AAAAC/hack-the-planet.gif)

# Why Reverse Engineering

If you're into programming, Reverse Engineering might be one of the most important skills to improve your programming knowledge.

Looking at other people code was always one of the best, if not the best way to learn new programming techniques. Now we all know that C and C++ Programs goes through a big process (Preprocessing, Tokenization, Optimizations, Assembling, Linking,...) that basically change the textual code into a binary executable for the Operating System you want.

![alt](https://files.gitbook.com/v0/b/gitbook-28427.appspot.com/o/assets%2F-Mk7MCiXZ7za0yxyehCg%2F-Mk7RfLlphCqkUO3SrCj%2F-Mk7Rv7gIyuteAZiRR4v%2Fimage.png?alt=media&token=a8fa223b-1f37-4781-b07d-f7b42dfb80c1)

Binary is a LOT more harder to understand and only a few binary ninjas are able to understand it, so unless the program is open-source you will potentially need to disassemble or decompile the binary, this is called Reverse Engineering, we take a compile executable (or binary), and we try to understand the code through either :

- Disassembly
	- Disassembly is the act of disassembling an executable or binary into it's assembly representation, the disassembling process can't be 100% perfect and they might be some errors to fixed in the disassembled code.

- Decompiling
	- Decompilation is the act of decompiling, we basically take a compiled binary and we tried to reverse that process to obtain a C / C++ representation of the binary or executable your currently analysing.

Knowing how to reverse a program will allow you to take any executable you want and look at what it does and how it truly does it things behind the scene.

Also Reverse Engineering, is useful for Malware Analysis, malwares uses a lot of different Obfuscation techniques, to make your life harder as an analyst, knowing how to counter these techniques and how to Deobfuscate programs will highly help you as a programmer.
