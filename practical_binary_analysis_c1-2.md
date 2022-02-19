# Symbols and Stripped Binaries
When compiling a program, compilers emits *symbols*, which keep track of such symbolic names and record which binary code and data correspond to each symbol.
## Viewing Symbolic Information
Let's use readelf and show what symbols looks like in a binary, for this i programmed a simple C program, which is the following.
```c
// Compile with gcc simple.c -o simple
#include <stdio.h>

void HelloWorld(){
	printf("Hello World !");
}


int main(int argc, char** argv, char** envp){
	HelloWorld();
	return 0;
}
```
Then we can extract the symbols with readelf like i previously said.
```
$ readelf --syms simple
Symbol table '.dynsym' contains 7 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     4: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     5: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]
     6: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND [...]@GLIBC_2.2.5 (2)

Symbol table '.symtab' contains 42 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS abi-note.c
     2: 000000000000039c    32 OBJECT  LOCAL  DEFAULT    4 __abi_tag
     3: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS init.c
     4: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
     5: 0000000000001070     0 FUNC    LOCAL  DEFAULT   14 deregister_tm_clones
     6: 00000000000010a0     0 FUNC    LOCAL  DEFAULT   14 register_tm_clones
     7: 00000000000010e0     0 FUNC    LOCAL  DEFAULT   14 __do_global_dtors_aux
     8: 0000000000004030     1 OBJECT  LOCAL  DEFAULT   25 completed.0
     9: 0000000000003df0     0 OBJECT  LOCAL  DEFAULT   20 __do_global_dtor[...]
    10: 0000000000001130     0 FUNC    LOCAL  DEFAULT   14 frame_dummy
    11: 0000000000003de8     0 OBJECT  LOCAL  DEFAULT   19 __frame_dummy_in[...]
    12: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS simple.c
    13: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
    14: 0000000000002144     0 OBJECT  LOCAL  DEFAULT   18 __FRAME_END__
    15: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS 
    16: 0000000000003df0     0 NOTYPE  LOCAL  DEFAULT   19 __init_array_end
    17: 0000000000003df8     0 OBJECT  LOCAL  DEFAULT   21 _DYNAMIC
    18: 0000000000003de8     0 NOTYPE  LOCAL  DEFAULT   19 __init_array_start
    19: 0000000000002014     0 NOTYPE  LOCAL  DEFAULT   17 __GNU_EH_FRAME_HDR
    20: 0000000000004000     0 OBJECT  LOCAL  DEFAULT   23 _GLOBAL_OFFSET_TABLE_
    21: 0000000000001000     0 FUNC    LOCAL  DEFAULT   12 _init
    22: 00000000000011f0     5 FUNC    GLOBAL DEFAULT   14 __libc_csu_fini
    23: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
    24: 0000000000004020     0 NOTYPE  WEAK   DEFAULT   24 data_start
    25: 0000000000001139    27 FUNC    GLOBAL DEFAULT   14 HelloWorld
    26: 0000000000004030     0 NOTYPE  GLOBAL DEFAULT   24 _edata
    27: 00000000000011f8     0 FUNC    GLOBAL HIDDEN    15 _fini
    28: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.2.5
    29: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_mai[...]
    30: 0000000000004020     0 NOTYPE  GLOBAL DEFAULT   24 __data_start
    31: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
    32: 0000000000004028     0 OBJECT  GLOBAL HIDDEN    24 __dso_handle
    33: 0000000000002000     4 OBJECT  GLOBAL DEFAULT   16 _IO_stdin_used
    34: 0000000000001180   101 FUNC    GLOBAL DEFAULT   14 __libc_csu_init
    35: 0000000000004038     0 NOTYPE  GLOBAL DEFAULT   25 _end
    36: 0000000000001040    47 FUNC    GLOBAL DEFAULT   14 _start
    37: 0000000000004030     0 NOTYPE  GLOBAL DEFAULT   25 __bss_start
    38: 0000000000001154    36 FUNC    GLOBAL DEFAULT   14 main
    39: 0000000000004030     0 OBJECT  GLOBAL HIDDEN    24 __TMC_END__
    40: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]
    41: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@G[...]
```
You can notice the symbol for the main function, it specify address 0x1154 at which main will reside when the binary is loaded into memory, you can also notice the size of the function in bytes, in this case the main function is 36 bytes long and that you're dealing with a function symbol (FUNC).

For ELF binaries, debugging symbols are typically generated in the DWARF format, while PE binaries usually use the proprietary Microsoft Portable Debugging (PDB) format. DWARF information is usually embedded within the binary, while PDB comes in the form of a separate symbol file.

Symbolic information is extremely useful for binary analysis, having access to functions symbol makes your analysis much more easier, this makes it much less likely that you'll accidentally disassemble data as code.

You can parse symbols with readelf, or programatically with a library like libbfd (we'll see it later), there are also libraries like libdwarf specifically designed for parsing DWARD debug symbols, but i won't cover them in this book.
## Stripping a Binary
By default, gcc does not strip binaries, however stripping a binary is as easy as it gets, the most common way to strip a binary is by using the *strip* binary that is included on most linux installations, you can strip a binary the following way.
```
$ strip --strip-all ./simple
```
Then we can use the *file* utility that also comes with most linux installations and see the output of this command.
```
$ file ./simple
simple: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2ff7abe06262630a9605e5580736cc5132eb5d25, for GNU/Linux 4.4.0, stripped
```
Notice how the file utility now says that the binary is stripped, well it in fact is stripped, let's now have some more fun and look at the symbols in the binary.
```
$ readelf --syms ./simple
Symbol table '.dynsym' contains 7 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     4: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     5: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]
     6: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND [...]@GLIBC_2.2.5 (2)
```
Our previously had 42 entries in the .symtab (symbol table), now the table is completely empty and contains no more symbolic information, note that the .dynsym table hasn't changed.