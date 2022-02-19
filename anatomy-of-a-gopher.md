# Anatomy of a Gopher 
This sections are my notes relating the SANS talk "Anatomy of a Gopher", by hex0punk (Alex Useche). The talk is still available on youtube at the following link [talk]("https://www.youtube.com/watch?v=wWNbnEp_4ZE").

## What are we doing
- Learning about what makes go binaries different than C and C++ binaries.
- Identifying techniques for recognizing and conducting analysis of go binaries.
- Tips for finding vulnerabilities in go binaries.
- Identifying common patterns found in go binaries.
- Learning about protections that can be added to go binaries.

## The GO Assembler
- The go compiler is based on plan9 compiler.
- Semi-abstract instruction set.
- Pseudo-Assembly.
- Not a direct representation of the underlying machine (i.e MOV may be a LD)
- It also introduces a set of pseudo registers (that you might not have seen before).

## Tools
- **Go Tool Objdump**
You can use **objdump** along with **go tool** to dump binary informations (functions, sections,...) 

You would typically use it the following way.
```
$ go tool objdump -s <func> <bin> 
$ go tool objdump <arguments> <bin>
```
A big advantage of using **go tool objdump** is that you get line numbers in code.This can help you group instructions by operations.

*Note that pretty much every disassembler does a great job at disassembling go binaries, this includes (r2, ghidra, ida, cutter, binary ninja, hopper, gdb,...).*

*Usually it is a best practice to use as many disassembler as you can and compare and catch on differences in the output, i usually like ghidra + ida or ida + binary ninja*

## Default Protections on Go Binaries
When you run go build, it should enable **NX** *(or No Execute if you prefer)* by default on the resulting binary. 

However note that **Position Independent Code (PIC or PIE) and Stack Canaries** are usually disabled **by default**, also note that binaries are not stripped.

ROP are a lot easier on go binaries since **PIC (or PIE)** is disabled by default.

#### How to enable protections on Go binaries.
- Enable Stack Protections `export CGO_LDFLAGS='-fstack-protector'`
- Strip the binary `GOOS=linux go build -ldflags="-s -w"`
- Enable PIE `export GOFLAGS='-buildmode=pie'`
- Strip functions names and reduce size `Get UPX and pack the file`

## Searching for Strings
Searching for strings in a go binary is a little harder than usual, because they are clumped together in a massive string table.

- Go does not store null terminated strings.
- Strings are clumped together, while keeping a separate table with length information.
- This can make it difficult to look for string cross-references.
- We can use a project like [gostringsr2](https://github.com/carvesystems/gostringsr2) to parse strings.
- When working with MachO binaries, you'd have to list strings from .rodata or entire binary

The usage of **grep** or filters is basically a must when looking at a go binary strings, because finding yourself in this massive string table can be quite hard.

**rabin2**
rabin2 is very useful when looking at go strings and is absolutely straightforward to use.
```
rabin2 -zz <binary> | grep <char.sequence>
```
*Just like with disassemblers, always use 2-3 different program when looking at strings and check for any differences, it might be hard to see with go binaries since they are statically linked, therefore all library strings should also be in the string table by default.*

## Searching for functions
Searching for functions is a lot easier than searching for strings in go binaries, which is the opposite of usual C/C++ binaries where strings are by default easier to find than functions.

Most of the time, even **stripped**, functions are still easy to find in go binaries, which is awesome to us anal-ysts.

## Finding the main function
Finding the main function is the easiest to find in go binaries, even in stripped ones... to find the main function look for either **main.main or main_main**.

## Go Stacks
An important thing to know about Go binaries is that they handle stacks differently, here's the main difference.
- Go routines have small stacks by default (2 kibibyte = 1024 bytes stack)
- Many goroutines will call **morestack** (sym.runtime.morestack_noctxt), to grow the stack (in powers of 2) as needed using stack copying.
- This is called because go can't be sure the function will outgrow the stack (i.e recursive functions) given non-deterministic goroutines.
- When this occurs, stack grows, pointers in the stack are updated.
- Additionally, each function compares its stack pointer against **g->stackguard** to check for overflow.
- Go uses 8 byte alignment on stack.

## Conventions (Arguments and Return Values)
Go binaries places return values on the stack, as opposed to C where return values are placed in registers (usually eax for x86).

As for return values, function arguments are also placed on the stack rather than registers.

*Understanding go internal libraries can significantly help us understand what is going on in the assembly code. Read the Go Docs !*

## Go Error Handling
- **error** is an interface.
- Error handling is clumsy in go.
- Bugs due to unhandled errors are common.
- When checking for **error != nil** we load the error vtable and error value.
- Then we test if the value is nil.
- And branch depending on the result.

## Reversing in action: Golang malware used in the SolarWinds attack (Kaspersky)
From now on, the notes are not related to the **Anatomy of Go video**, but on this [Kaspersky course](https://www.youtube.com/watch?v=_cL-OwU9pFQ). I highly recommend that you go watch the video too.

This course is an absolute pearl and helped me a lot learn more about Go and Reverse Engineering, we focus principally on reversing a piece of malware that was used in the SolarWinds breach a little earlier this year, the malware in question is **SunShuttle**.


