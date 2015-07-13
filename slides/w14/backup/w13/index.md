
---
title: Misc
---

# pwntools

## Installation
+ python
+ pip
+ [pwntools](https://github.com/Gallopsled/pwntools.git)

## python
+ pyenv is useful for non-root user
+ `https://github.com/yyuu/pyenv`
+ `pyenv install 2.7.8`
+ `pyenv versions`
+ `pyenv global 2.7.8`
+ `pyenv rehash`

## pwntools
+ `https://github.com/Gallopsled/pwntools.git`
+ `http://pwntools.readthedocs.org/en/latest/`

## Useful toolkits
+ remote
+ asm / disasm
+ ELF
+ rop
+ dynELF

# x86-64

## 64-bit x86 Architecture
+ Registers
+ Stack
+ Memory address
+ System calls
+ Calling conventions

## Registers
+ `rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi` 
+ `r8, r9, r10, r11, r12, r13, r14, r15`
+ 32-bit `r8d, r9d, ..., r15d`


## Stack
+ Each stack entry is 64-bit wide

## Move QWORD to a 64-bit Registor
+ `mov rax, 0xdeadbeef123` in NASM, but actually `movabs rax, 0xdeadbeef123` in objdump, gdb

## Memory Address
+ 64-bit address, also may include ASLR
+ Example:
    + Code .text `00400000`, .data `00600000`
    + Libc `7f6f38e1a000`
    + Heap `0230e000`
    + Stack `7fff627f6000`
+ `gcc -pie -fPIE`
    + Code .text `7f2e8ec6a000`, .data `7f2e8ee6a000`
    + Libc `7f2e8e67f000`
    + Heap `7f2e8f262000`
    + Stack `7fff31602000`

## System Calls
+ Difference
    + System call numbers
    + Registers
+ [Syscall table](http://blog.rchapman.org/post/36801038863/linux-system-call-table-for-x86-64)

``` avrasm
section .text
global _start
_start:
  mov rax, 1
  mov rdi, 1
  mov rsi, str
  mov rdx, 6
  syscall

  mov rax, 60
  syscall
str:
  db 'hello',0xA
```

## Calling conventions on Linux
+ Return value: `rax`
+ **Arguments:** `rdi, rsi, rdx, rcx, r8, r9` and then stack

## ROP
+ Quite difficult ...
+ Need gadgets for controlling arguments

## ROP Example

``` cpp
#include <stdio.h>

int main() {
  char buf[8];
  read(0, buf, 1024);
  return 0;
}
```

## Use pwntools
+ Assumed that we do not have libc.so.6 now
+ Construct function calls
+ Function calls combo
+ Construct a leaker 
+ Resolve symbol, find `system()`
+ Construct a `system('/bin/sh')`

# ARM

## Tools
+ gcc-4.8-arm-linux-gnueabihf
    + arm-linux-gnueabihf-gcc-4.8
    + arm-linux-gnueabihf-objdump
+ g++-4.8-arm-linux-gnueabihf
+ qemu
    + qemu-arm
    + qemu-system-arm
+ gdb-multiarch
+ IDA & armlinux_server

## qemu-system
+ [https://people.debian.org/~aurel32/qemu/](https://people.debian.org/~aurel32/qemu/)
+ qemu-system-arm -M versatilepb -kernel vmlinuz-3.2.0-4-versatile -initrd initrd.img-3.2.0-4-versatile -hda debian_wheezy_armel_standard.qcow2 -append "root=/dev/sda1" -nographic -redir tcp:2222::22 -redir tcp:23947::23946
+ Login with root/root

## qemu-user & gdb-multiarch
+ Library needed: /usr/arm-linux-gnueabi/lib/
+ qemu-arm -g 4444 -E LD_LIBRARY_PATH=/usr/arm-linux-gnueabi/lib /usr/arm-linux-gnueabi/lib/ld-2.19.so ./bina
+ gdb-multiarch ./bina
    + target remote localhost:4444

## Demo
+ Buffer overflow
+ Jump to shellcode

