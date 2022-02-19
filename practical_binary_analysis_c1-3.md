# Disassembling a Binary
Now that we wen't through the compilation process and a little bit into symbolic informations inside binaries, we can start trying to disassemble an executable and see how it differs from an object file.
## Looking inside an Object File
For this we will use the *objdump* utility for linux, it's a simple, easy-to-use disassembler included with most linux distributions.
```
$ objdump -sj .rodata simple.o
simple.o:     file format elf64-x86-64

Contents of section .rodata:
 0000 48656c6c 6f20576f 726c6420 2100      Hello World !.  
 
$ objdump -M intel -d simple.o
simple.o:     file format elf64-x86-64
Disassembly of section .text:

0000000000000000 <HelloWorld>:
   0:   55                      push   rbp
   1:   48 89 e5                mov    rbp,rsp
   4:   48 8d 05 00 00 00 00    lea    rax,[rip+0x0]        # b <HelloWorld+0xb>
   b:   48 89 c7                mov    rdi,rax
   e:   b8 00 00 00 00          mov    eax,0x0
  13:   e8 00 00 00 00          call   18 <HelloWorld+0x18>
  18:   90                      nop
  19:   5d                      pop    rbp
  1a:   c3                      ret    

000000000000001b <main>:
  1b:   55                      push   rbp
  1c:   48 89 e5                mov    rbp,rsp
  1f:   48 83 ec 20             sub    rsp,0x20
  23:   89 7d fc                mov    DWORD PTR [rbp-0x4],edi
  26:   48 89 75 f0             mov    QWORD PTR [rbp-0x10],rsi
  2a:   48 89 55 e8             mov    QWORD PTR [rbp-0x18],rdx
  2e:   b8 00 00 00 00          mov    eax,0x0
  33:   e8 00 00 00 00          call   38 <main+0x1d>
  38:   b8 00 00 00 00          mov    eax,0x0
  3d:   c9                      leave  
  3e:   c3                      ret 
```
The first time we called objdump we are asking for the content of the .rodata (read only data) section, in our case we have only "Hello World !" which is a string constant.

The contents of .rodata consist of an ASCII encoding of the string, shown on the left side of the output, on the right side you can see the human representation of those bytes.

The second call to objdump disassembles all the code of the functions inside our binary, the output conforms pretty closely to the assembly code previously produced by the compilation phase.

Note that the offsets in an object file doesn't really make sense, like the call to the HelloWorld function or the pointer to the string "Hello World" in the function HelloWorld supposedly at `[rip+0x0]` which doesn't really make any sense, this happens because data and code references from obejct files are not yet fully resolved because the compiler doesn't know at what base address the file will eventually be loaded. The object file is waiting for the linker to fill in the correct value for this reference.

You can confirm this by asking readelf to show you all the relocation symbols present in the object file.
```
$ readelf --relocs simple.o
Relocation section '.rela.text' at offset 0x220 contains 3 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000000007  000300000002 R_X86_64_PC32     0000000000000000 .rodata - 4
000000000014  000600000004 R_X86_64_PLT32    0000000000000000 printf - 4
000000000034  000400000004 R_X86_64_PLT32    0000000000000000 HelloWorld - 4
...
```
The relocation `.rodata - 4` tells the linker that it should resolve the reference to the string to point to whatever address it ends up at in the `.rodata` section.

The relocation `printf - 4` is telling the linker how to resolve the call to puts, same thing with `HelloWorld - 4`.
## Examining a Complete Binary Executable
Now that you've seen the innards of an object file, it's time to disassemble a complete binary. We will first disassembler a regular binary and after we will disassemble a stripped one, this should make it easier for us to see the difference between both.
```x86asm
$ objdump -M intel -d simple
simple:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:       f3 0f 1e fa             endbr64 
    1004:       48 83 ec 08             sub    rsp,0x8
    1008:       48 8b 05 d9 2f 00 00    mov    rax,QWORD PTR [rip+0x2fd9]        # 3fe8 <__gmon_start__>
    100f:       48 85 c0                test   rax,rax
    1012:       74 02                   je     1016 <_init+0x16>
    1014:       ff d0                   call   rax
    1016:       48 83 c4 08             add    rsp,0x8
    101a:       c3                      ret    

Disassembly of section .plt:

0000000000001020 <printf@plt-0x10>:
    1020:       ff 35 e2 2f 00 00       push   QWORD PTR [rip+0x2fe2]        # 4008 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:       ff 25 e4 2f 00 00       jmp    QWORD PTR [rip+0x2fe4]        # 4010 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:       0f 1f 40 00             nop    DWORD PTR [rax+0x0]

0000000000001030 <printf@plt>:
    1030:       ff 25 e2 2f 00 00       jmp    QWORD PTR [rip+0x2fe2]        # 4018 <printf@GLIBC_2.2.5>
    1036:       68 00 00 00 00          push   0x0
    103b:       e9 e0 ff ff ff          jmp    1020 <_init+0x20>

Disassembly of section .text:

0000000000001040 <_start>:
    1040:       f3 0f 1e fa             endbr64 
    1044:       31 ed                   xor    ebp,ebp
    1046:       49 89 d1                mov    r9,rdx
    1049:       5e                      pop    rsi
    104a:       48 89 e2                mov    rdx,rsp
    104d:       48 83 e4 f0             and    rsp,0xfffffffffffffff0
    1051:       50                      push   rax
    1052:       54                      push   rsp
    1053:       4c 8d 05 96 01 00 00    lea    r8,[rip+0x196]        # 11f0 <__libc_csu_fini>
    105a:       48 8d 0d 1f 01 00 00    lea    rcx,[rip+0x11f]        # 1180 <__libc_csu_init>
    1061:       48 8d 3d ec 00 00 00    lea    rdi,[rip+0xec]        # 1154 <main>
    1068:       ff 15 72 2f 00 00       call   QWORD PTR [rip+0x2f72]        # 3fe0 <__libc_start_main@GLIBC_2.2.5>
    106e:       f4                      hlt    
    106f:       90                      nop

0000000000001070 <deregister_tm_clones>:
    1070:       48 8d 3d b9 2f 00 00    lea    rdi,[rip+0x2fb9]        # 4030 <__TMC_END__>
    1077:       48 8d 05 b2 2f 00 00    lea    rax,[rip+0x2fb2]        # 4030 <__TMC_END__>
    107e:       48 39 f8                cmp    rax,rdi
    1081:       74 15                   je     1098 <deregister_tm_clones+0x28>
    1083:       48 8b 05 4e 2f 00 00    mov    rax,QWORD PTR [rip+0x2f4e]        # 3fd8 <_ITM_deregisterTMCloneTable>
    108a:       48 85 c0                test   rax,rax
    108d:       74 09                   je     1098 <deregister_tm_clones+0x28>
    108f:       ff e0                   jmp    rax
    1091:       0f 1f 80 00 00 00 00    nop    DWORD PTR [rax+0x0]
    1098:       c3                      ret    
    1099:       0f 1f 80 00 00 00 00    nop    DWORD PTR [rax+0x0]

00000000000010a0 <register_tm_clones>:
    10a0:       48 8d 3d 89 2f 00 00    lea    rdi,[rip+0x2f89]        # 4030 <__TMC_END__>
    10a7:       48 8d 35 82 2f 00 00    lea    rsi,[rip+0x2f82]        # 4030 <__TMC_END__>
    10ae:       48 29 fe                sub    rsi,rdi
    10b1:       48 89 f0                mov    rax,rsi
    10b4:       48 c1 ee 3f             shr    rsi,0x3f
    10b8:       48 c1 f8 03             sar    rax,0x3
    10bc:       48 01 c6                add    rsi,rax
    10bf:       48 d1 fe                sar    rsi,1
    10c2:       74 14                   je     10d8 <register_tm_clones+0x38>
    10c4:       48 8b 05 25 2f 00 00    mov    rax,QWORD PTR [rip+0x2f25]        # 3ff0 <_ITM_registerTMCloneTable>
    10cb:       48 85 c0                test   rax,rax
    10ce:       74 08                   je     10d8 <register_tm_clones+0x38>
    10d0:       ff e0                   jmp    rax
    10d2:       66 0f 1f 44 00 00       nop    WORD PTR [rax+rax*1+0x0]
    10d8:       c3                      ret    
    10d9:       0f 1f 80 00 00 00 00    nop    DWORD PTR [rax+0x0]

00000000000010e0 <__do_global_dtors_aux>:
    10e0:       f3 0f 1e fa             endbr64 
    10e4:       80 3d 45 2f 00 00 00    cmp    BYTE PTR [rip+0x2f45],0x0        # 4030 <__TMC_END__>
    10eb:       75 33                   jne    1120 <__do_global_dtors_aux+0x40>
    10ed:       55                      push   rbp
    10ee:       48 83 3d 02 2f 00 00    cmp    QWORD PTR [rip+0x2f02],0x0        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    10f5:       00 
    10f6:       48 89 e5                mov    rbp,rsp
    10f9:       74 0d                   je     1108 <__do_global_dtors_aux+0x28>
    10fb:       48 8b 3d 26 2f 00 00    mov    rdi,QWORD PTR [rip+0x2f26]        # 4028 <__dso_handle>
    1102:       ff 15 f0 2e 00 00       call   QWORD PTR [rip+0x2ef0]        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1108:       e8 63 ff ff ff          call   1070 <deregister_tm_clones>
    110d:       c6 05 1c 2f 00 00 01    mov    BYTE PTR [rip+0x2f1c],0x1        # 4030 <__TMC_END__>
    1114:       5d                      pop    rbp
    1115:       c3                      ret    
    1116:       66 2e 0f 1f 84 00 00    cs nop WORD PTR [rax+rax*1+0x0]
    111d:       00 00 00 
    1120:       c3                      ret    
    1121:       66 66 2e 0f 1f 84 00    data16 cs nop WORD PTR [rax+rax*1+0x0]
    1128:       00 00 00 00 
    112c:       0f 1f 40 00             nop    DWORD PTR [rax+0x0]

0000000000001130 <frame_dummy>:
    1130:       f3 0f 1e fa             endbr64 
    1134:       e9 67 ff ff ff          jmp    10a0 <register_tm_clones>

0000000000001139 <HelloWorld>:
    1139:       55                      push   rbp
    113a:       48 89 e5                mov    rbp,rsp
    113d:       48 8d 05 c0 0e 00 00    lea    rax,[rip+0xec0]        # 2004 <_IO_stdin_used+0x4>
    1144:       48 89 c7                mov    rdi,rax
    1147:       b8 00 00 00 00          mov    eax,0x0
    114c:       e8 df fe ff ff          call   1030 <printf@plt>
    1151:       90                      nop
    1152:       5d                      pop    rbp
    1153:       c3                      ret    

0000000000001154 <main>:
    1154:       55                      push   rbp
    1155:       48 89 e5                mov    rbp,rsp
    1158:       48 83 ec 20             sub    rsp,0x20
    115c:       89 7d fc                mov    DWORD PTR [rbp-0x4],edi
    115f:       48 89 75 f0             mov    QWORD PTR [rbp-0x10],rsi
    1163:       48 89 55 e8             mov    QWORD PTR [rbp-0x18],rdx
    1167:       b8 00 00 00 00          mov    eax,0x0
    116c:       e8 c8 ff ff ff          call   1139 <HelloWorld>
    1171:       b8 00 00 00 00          mov    eax,0x0
    1176:       c9                      leave  
    1177:       c3                      ret    
    1178:       0f 1f 84 00 00 00 00    nop    DWORD PTR [rax+rax*1+0x0]
    117f:       00 

0000000000001180 <__libc_csu_init>:
    1180:       f3 0f 1e fa             endbr64 
    1184:       41 57                   push   r15
    1186:       4c 8d 3d 5b 2c 00 00    lea    r15,[rip+0x2c5b]        # 3de8 <__frame_dummy_init_array_entry>
    118d:       41 56                   push   r14
    118f:       49 89 d6                mov    r14,rdx
    1192:       41 55                   push   r13
    1194:       49 89 f5                mov    r13,rsi
    1197:       41 54                   push   r12
    1199:       41 89 fc                mov    r12d,edi
    119c:       55                      push   rbp
    119d:       48 8d 2d 4c 2c 00 00    lea    rbp,[rip+0x2c4c]        # 3df0 <__do_global_dtors_aux_fini_array_entry>
    11a4:       53                      push   rbx
    11a5:       4c 29 fd                sub    rbp,r15
    11a8:       48 83 ec 08             sub    rsp,0x8
    11ac:       e8 4f fe ff ff          call   1000 <_init>
    11b1:       48 c1 fd 03             sar    rbp,0x3
    11b5:       74 1f                   je     11d6 <__libc_csu_init+0x56>
    11b7:       31 db                   xor    ebx,ebx
    11b9:       0f 1f 80 00 00 00 00    nop    DWORD PTR [rax+0x0]
    11c0:       4c 89 f2                mov    rdx,r14
    11c3:       4c 89 ee                mov    rsi,r13
    11c6:       44 89 e7                mov    edi,r12d
    11c9:       41 ff 14 df             call   QWORD PTR [r15+rbx*8]
    11cd:       48 83 c3 01             add    rbx,0x1
    11d1:       48 39 dd                cmp    rbp,rbx
    11d4:       75 ea                   jne    11c0 <__libc_csu_init+0x40>
    11d6:       48 83 c4 08             add    rsp,0x8
    11da:       5b                      pop    rbx
    11db:       5d                      pop    rbp
    11dc:       41 5c                   pop    r12
    11de:       41 5d                   pop    r13
    11e0:       41 5e                   pop    r14
    11e2:       41 5f                   pop    r15
    11e4:       c3                      ret    
    11e5:       66 66 2e 0f 1f 84 00    data16 cs nop WORD PTR [rax+rax*1+0x0]
    11ec:       00 00 00 00 

00000000000011f0 <__libc_csu_fini>:
    11f0:       f3 0f 1e fa             endbr64 
    11f4:       c3                      ret    

Disassembly of section .fini:

00000000000011f8 <_fini>:
    11f8:       f3 0f 1e fa             endbr64 
    11fc:       48 83 ec 08             sub    rsp,0x8
    1200:       48 83 c4 08             add    rsp,0x8
    1204:       c3                      ret   
```
There is a lot more code in the binary than the object file, it's not longer just our 2 functions. There are multiple sections now, with names like `.init`, `.plt` and `.text`. These sections all contain code serving different functions, such as program initialization or stubs for calling shared libraries.

### .text section
contains the `main code section`, this is where the `main function should reside`. It also `contains a number of other functions, such as \_start`, that are **responsible for tasks such as setting up the command line arguments and runtime environment for main and cleaning up after main**. These extra functions are standard functions, **present in any ELF binary produced by gcc**. 

You can also see that the previously incomplete code and data references have now been resolved by the linker. For instance, the call to `HelloWorld` is properly resolved and `printf` points to the proper stub (**in the .plt section**) for the shared library that contain puts (**libc**).

The binary might contains a whole lot of other functions and code but it is still pretty much the same thing we reversed in our object file, this will change when we will strip the binary.
```x86asm
$ objdump -M intel -d simple.stripped
simple.stripped:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <.init>:
    1000:       f3 0f 1e fa             endbr64 
    1004:       48 83 ec 08             sub    rsp,0x8
    1008:       48 8b 05 d9 2f 00 00    mov    rax,QWORD PTR [rip+0x2fd9]        # 3fe8 <printf@plt+0x2fb8>
    100f:       48 85 c0                test   rax,rax
    1012:       74 02                   je     1016 <printf@plt-0x1a>
    1014:       ff d0                   call   rax
    1016:       48 83 c4 08             add    rsp,0x8
    101a:       c3                      ret    

Disassembly of section .plt:

0000000000001020 <printf@plt-0x10>:
    1020:       ff 35 e2 2f 00 00       push   QWORD PTR [rip+0x2fe2]        # 4008 <printf@plt+0x2fd8>
    1026:       ff 25 e4 2f 00 00       jmp    QWORD PTR [rip+0x2fe4]        # 4010 <printf@plt+0x2fe0>
    102c:       0f 1f 40 00             nop    DWORD PTR [rax+0x0]

0000000000001030 <printf@plt>:
    1030:       ff 25 e2 2f 00 00       jmp    QWORD PTR [rip+0x2fe2]        # 4018 <printf@plt+0x2fe8>
    1036:       68 00 00 00 00          push   0x0
    103b:       e9 e0 ff ff ff          jmp    1020 <printf@plt-0x10>

Disassembly of section .text:

0000000000001040 <.text>:
    1040:       f3 0f 1e fa             endbr64 
    1044:       31 ed                   xor    ebp,ebp
    1046:       49 89 d1                mov    r9,rdx
    1049:       5e                      pop    rsi
    104a:       48 89 e2                mov    rdx,rsp
    104d:       48 83 e4 f0             and    rsp,0xfffffffffffffff0
    1051:       50                      push   rax
    1052:       54                      push   rsp
    1053:       4c 8d 05 96 01 00 00    lea    r8,[rip+0x196]        # 11f0 <printf@plt+0x1c0>
    105a:       48 8d 0d 1f 01 00 00    lea    rcx,[rip+0x11f]        # 1180 <printf@plt+0x150>
    1061:       48 8d 3d ec 00 00 00    lea    rdi,[rip+0xec]        # 1154 <printf@plt+0x124>
    1068:       ff 15 72 2f 00 00       call   QWORD PTR [rip+0x2f72]        # 3fe0 <printf@plt+0x2fb0>
    106e:       f4                      hlt    
    106f:       90                      nop
    1070:       48 8d 3d b9 2f 00 00    lea    rdi,[rip+0x2fb9]        # 4030 <printf@plt+0x3000>
    1077:       48 8d 05 b2 2f 00 00    lea    rax,[rip+0x2fb2]        # 4030 <printf@plt+0x3000>
    107e:       48 39 f8                cmp    rax,rdi
    1081:       74 15                   je     1098 <printf@plt+0x68>
    1083:       48 8b 05 4e 2f 00 00    mov    rax,QWORD PTR [rip+0x2f4e]        # 3fd8 <printf@plt+0x2fa8>
    108a:       48 85 c0                test   rax,rax
    108d:       74 09                   je     1098 <printf@plt+0x68>
    108f:       ff e0                   jmp    rax
    1091:       0f 1f 80 00 00 00 00    nop    DWORD PTR [rax+0x0]
    1098:       c3                      ret    
    1099:       0f 1f 80 00 00 00 00    nop    DWORD PTR [rax+0x0]
    10a0:       48 8d 3d 89 2f 00 00    lea    rdi,[rip+0x2f89]        # 4030 <printf@plt+0x3000>
    10a7:       48 8d 35 82 2f 00 00    lea    rsi,[rip+0x2f82]        # 4030 <printf@plt+0x3000>
    10ae:       48 29 fe                sub    rsi,rdi
    10b1:       48 89 f0                mov    rax,rsi
    10b4:       48 c1 ee 3f             shr    rsi,0x3f
    10b8:       48 c1 f8 03             sar    rax,0x3
    10bc:       48 01 c6                add    rsi,rax
    10bf:       48 d1 fe                sar    rsi,1
    10c2:       74 14                   je     10d8 <printf@plt+0xa8>
    10c4:       48 8b 05 25 2f 00 00    mov    rax,QWORD PTR [rip+0x2f25]        # 3ff0 <printf@plt+0x2fc0>
    10cb:       48 85 c0                test   rax,rax
    10ce:       74 08                   je     10d8 <printf@plt+0xa8>
    10d0:       ff e0                   jmp    rax
    10d2:       66 0f 1f 44 00 00       nop    WORD PTR [rax+rax*1+0x0]
    10d8:       c3                      ret    
    10d9:       0f 1f 80 00 00 00 00    nop    DWORD PTR [rax+0x0]
    10e0:       f3 0f 1e fa             endbr64 
    10e4:       80 3d 45 2f 00 00 00    cmp    BYTE PTR [rip+0x2f45],0x0        # 4030 <printf@plt+0x3000>
    10eb:       75 33                   jne    1120 <printf@plt+0xf0>
    10ed:       55                      push   rbp
    10ee:       48 83 3d 02 2f 00 00    cmp    QWORD PTR [rip+0x2f02],0x0        # 3ff8 <printf@plt+0x2fc8>
    10f5:       00 
    10f6:       48 89 e5                mov    rbp,rsp
    10f9:       74 0d                   je     1108 <printf@plt+0xd8>
    10fb:       48 8b 3d 26 2f 00 00    mov    rdi,QWORD PTR [rip+0x2f26]        # 4028 <printf@plt+0x2ff8>
    1102:       ff 15 f0 2e 00 00       call   QWORD PTR [rip+0x2ef0]        # 3ff8 <printf@plt+0x2fc8>
    1108:       e8 63 ff ff ff          call   1070 <printf@plt+0x40>
    110d:       c6 05 1c 2f 00 00 01    mov    BYTE PTR [rip+0x2f1c],0x1        # 4030 <printf@plt+0x3000>
    1114:       5d                      pop    rbp
    1115:       c3                      ret    
    1116:       66 2e 0f 1f 84 00 00    cs nop WORD PTR [rax+rax*1+0x0]
    111d:       00 00 00 
    1120:       c3                      ret    
    1121:       66 66 2e 0f 1f 84 00    data16 cs nop WORD PTR [rax+rax*1+0x0]
    1128:       00 00 00 00 
    112c:       0f 1f 40 00             nop    DWORD PTR [rax+0x0]
    1130:       f3 0f 1e fa             endbr64 
    1134:       e9 67 ff ff ff          jmp    10a0 <printf@plt+0x70>
    1139:       55                      push   rbp
    113a:       48 89 e5                mov    rbp,rsp
    113d:       48 8d 05 c0 0e 00 00    lea    rax,[rip+0xec0]        # 2004 <printf@plt+0xfd4>
    1144:       48 89 c7                mov    rdi,rax
    1147:       b8 00 00 00 00          mov    eax,0x0
    114c:       e8 df fe ff ff          call   1030 <printf@plt>
    1151:       90                      nop
    1152:       5d                      pop    rbp
    1153:       c3                      ret    
    1154:       55                      push   rbp
    1155:       48 89 e5                mov    rbp,rsp
    1158:       48 83 ec 20             sub    rsp,0x20
    115c:       89 7d fc                mov    DWORD PTR [rbp-0x4],edi
    115f:       48 89 75 f0             mov    QWORD PTR [rbp-0x10],rsi
    1163:       48 89 55 e8             mov    QWORD PTR [rbp-0x18],rdx
    1167:       b8 00 00 00 00          mov    eax,0x0
    116c:       e8 c8 ff ff ff          call   1139 <printf@plt+0x109>
    1171:       b8 00 00 00 00          mov    eax,0x0
    1176:       c9                      leave  
    1177:       c3                      ret    
    1178:       0f 1f 84 00 00 00 00    nop    DWORD PTR [rax+rax*1+0x0]
    117f:       00 
    1180:       f3 0f 1e fa             endbr64 
    1184:       41 57                   push   r15
    1186:       4c 8d 3d 5b 2c 00 00    lea    r15,[rip+0x2c5b]        # 3de8 <printf@plt+0x2db8>
    118d:       41 56                   push   r14
    118f:       49 89 d6                mov    r14,rdx
    1192:       41 55                   push   r13
    1194:       49 89 f5                mov    r13,rsi
    1197:       41 54                   push   r12
    1199:       41 89 fc                mov    r12d,edi
    119c:       55                      push   rbp
    119d:       48 8d 2d 4c 2c 00 00    lea    rbp,[rip+0x2c4c]        # 3df0 <printf@plt+0x2dc0>
    11a4:       53                      push   rbx
    11a5:       4c 29 fd                sub    rbp,r15
    11a8:       48 83 ec 08             sub    rsp,0x8
    11ac:       e8 4f fe ff ff          call   1000 <printf@plt-0x30>
    11b1:       48 c1 fd 03             sar    rbp,0x3
    11b5:       74 1f                   je     11d6 <printf@plt+0x1a6>
    11b7:       31 db                   xor    ebx,ebx
    11b9:       0f 1f 80 00 00 00 00    nop    DWORD PTR [rax+0x0]
    11c0:       4c 89 f2                mov    rdx,r14
    11c3:       4c 89 ee                mov    rsi,r13
    11c6:       44 89 e7                mov    edi,r12d
    11c9:       41 ff 14 df             call   QWORD PTR [r15+rbx*8]
    11cd:       48 83 c3 01             add    rbx,0x1
    11d1:       48 39 dd                cmp    rbp,rbx
    11d4:       75 ea                   jne    11c0 <printf@plt+0x190>
    11d6:       48 83 c4 08             add    rsp,0x8
    11da:       5b                      pop    rbx
    11db:       5d                      pop    rbp
    11dc:       41 5c                   pop    r12
    11de:       41 5d                   pop    r13
    11e0:       41 5e                   pop    r14
    11e2:       41 5f                   pop    r15
    11e4:       c3                      ret    
    11e5:       66 66 2e 0f 1f 84 00    data16 cs nop WORD PTR [rax+rax*1+0x0]
    11ec:       00 00 00 00 
    11f0:       f3 0f 1e fa             endbr64 
    11f4:       c3                      ret    

Disassembly of section .fini:

00000000000011f8 <.fini>:
    11f8:       f3 0f 1e fa             endbr64 
    11fc:       48 83 ec 08             sub    rsp,0x8
    1200:       48 83 c4 08             add    rsp,0x8
    1204:       c3                      ret 
```
The main takeaway is that while the different sections are still clearly distinguishable, the functions are not. Instead all the functions have been merged into one big blob of code. Notice how stripped binaries can make your life much harder as a reverse engineer.
## Loading and Executing a Binary
Now you know how compilation works as well as how binaries look on the inside. You also learned how to statically disassemble binaries using objdump. Now it's time to learn what actually happens when you load and execute a binary.

Although the exact details vary depending on the platform and binary format, the process of loading and executing a binary typically involves a number of basic steps the following picture shows how a loaded ELF binary (like the one just compiled) is represented in memory on a Linux-based platform. At a high level, loading a PE binary on Windows is quite similar.
  
![](https://i.imgur.com/4db89Jd.png)

Loading a binary is a complicated process that involves a lot of work by the operating system. It's also important to note that a binary representation in memory does not necessarily correspond one-to-one with its on-disk representation. For instance, large regions of zero initialized data may be collapsed in the on-disk binary (to save disk space), while all those zeros will be expanded in memory. Some parts of the on-disk binary may be ordered differently in memory or not loaded into memory at all.

When you decide to run a binary the operating system starts by setting up a new process for the program to run in, including a virtual address space. Subsequently, the operating system maps an interpreter into the process virtual memory. This is a user space program that knows how to load the binary and perform the necessary relocations.  On Linux, the interpreter is typically a shared library called *ld-linux.so*. On Windows, the interpreter functionality is implemented as part of *ntdll.dll*. After loading the interpreter, the kernel transfers control to it, and the interpreter begins its work in user space.

Linux ELF binaries come with a special section called .interp that specifies the path to the interpreter that is to be used to load the binary.
```
$ readelf -p .interp simple
String dump of section '.interp':
  [     0]  /lib64/ld-linux-x86-64.so.2

```
As mentionned, the interpreter loads the binary into its virtual address space (the same space in which the interpreter is loaded). It then parses the binary to find out (among other things) which dynamic libraries the binary uses. The interpreter maps these into the virtual address space (using mmap or an equivalent function) and then performs any necessary last-minute relocations in the binary's code sections to fill in the correct addresses for references to the dynamic libaries. In reality, the process of resolving references to functions in dynamic libraries is often deferred until later.