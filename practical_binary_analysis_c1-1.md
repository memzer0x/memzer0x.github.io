# The C Compilation Process
Binaries goes through a process called *compilation*, which is the process of translating human readable source code, such as C or C++, into machine code that your processor can execute.
#### 1 - Preprocessing
Includes are included inside the main source file (library code), same thing with other header files and source files, macros definitions in code are replaced with the value of the macro instead of the name of this one, therefore any macros should lose it's symbolic name after preprocessing.
#### 2 - Compilation
When preprocessing is done, the source is ready to be compiled. Compilations consists of taking C/C++ source code and transforming it into assembly. (Most compilers also perform heavy optimization in this phase).
#### 3 - Assembly Phase
After compilation of our code into assembly, it's time to transform it into machine code. The input of the assembly phase is the set of assembly language files generated in the compilation phase, and the output is a set of *object files*, sometimes also referred to as *modules*. Object files contains machine instructions that are in principle executable by the processor.

GCC can be used to generate object files instead of ELF executable, this is easily done using the -c switch.
```
$ gcc -c source.c
$ file source.o
source.o: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped
```
What does *Relocatable* means ? Relocatable files don't rely on being placed at any particular address in memory; rather, they can be moved around at will without breaking any assumptions in the code. When you see the term *relocatable* in the *file* output, you know you are dealing with an object file and not an executable.

Object files are compiled independently from each other, so the assembler has no way of knowing the memory addresses of other object files when assembling an object file. That's why object files need to be relocatable; that way, you can link them together in any order to form a complete binary executable. If object files were not relocatable, this would not be possible.
#### 4 - Linking
The linking phase is the last and final phase of the ELF compilation process, this phase is responsible for linking all the generated object files from the last phase into a single ELF executable, in modern systems, the linking phase sometimes incorporates an additional optimization pass, called *link-time optimization (LTO).*

The program responsible for linking the obect files is called the *linker*. It's typically seperate from the compiler.

Object files are relocatable because they are compiled independently from each other, preventing the compiler from assuming that an object will end up at any particular base address. Moreover, object files may reference functions or variables in other object files or in libraries that are external to the program (example libc). Before the linking phase the addresses at which the referenced code and data will be placed are not yet known, so the object files only contain *relocation symbols* that specify how function and variable references should eventually be resolved. In the context of linking, references that rely on a relocation are called *symbolic references*.

The linker's job is to take all the object files belonging to a program and merge them into a single coherent executable, typically intended to be loaded at a particular memory address. Now that the arrangement of all modules in the executable is known, the linker can resolve most symbolic references. References to libraries may or may not be completely resolved, depending on the type of library.

Static libraries (which on linux typically have the extension .a) are merged into the binary executable, allowing any references to them to be resolved entirely. There are also dynamic (shared) libraries, which are shared in memory among all programs that run on a system. In other words, rather than copying all the library into every binary that uses it, dynamic libraries are loaded into memory only once, and any binary that wants to use the library needs to use this shared copy. During the linking phase, the addresses at which dynamic libraries will reside are not yet known, so references to them cannot be resolved. Instead the linker leaves symbolic references to these libraries even in the final executable and these references are not resolved until the binary is actually loaded into memory to be executed.

You can see which dynamic linker and shared libraries will be used by your executable by running the ldd command on it (works only with dynamically linked libraries).