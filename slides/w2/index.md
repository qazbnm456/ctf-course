
---
title: x86 Linux Programming
---

## Overview
+ 32-bit x86 assembly language
+ system call
+ stack & calling convention
+ ELF & dynamically linking
+ Shellcode tricks

# Tutorial: x86 ASM

## Done!
Intel&reg; 64 and IA-32 Architectures<br>Software Developer's Manual<br>
(共 3439 頁)

## x86 is Complex!
+ [元素表 (opcode)](http://sparksandflames.com/files/x86InstructionChart.html)
+ [無用小知識](https://code.google.com/p/corkami/wiki/x86oddities)

## 無用小知識

+ `lock add qword cs:[eax + 4 * eax + 07e06df23h], 0efcdab89h`
+ `aeskeygenassist`

## 準備工具
+ nasm
+ objdump
+ gcc
+ gdb
+ Editor
+ x86 Linux machine (CSIE Workstation is fine)

``` no-highlight
$ lscpu
Architecture:          x86_64
CPU op-mode(s):        32-bit, 64-bit
Byte Order:            Little Endian
... 
```

## 32-bit x86 Assembly Language
+ Intel syntax
+ Use nasm for assembling
+ `gcc -m32` 可以編出 32-bit binary，預設會是 64-bit (apt-get install gcc-multilib)

## NASM
+ `apt-get install nasm`
+ `nasm -felf32 a.asm -o a.o && ld a.o -melf_i386 -o a`
+ 有一些好用的語法 extension

## Example: Assemble & Disassemble

`nasm -felf32 a.asm -o a.o && ld a.o -melf_i386 -o a`
``` avrasm
section .text
global _start
_start:
    mov eax, 0x1337
    add ebx, eax
    jmp _start
```

`objdump -M intel -d ./a`
``` no-highlight
00000000 <_start>:
   0:   b8 37 13 00 00          mov    eax,0x1337
   5:   01 c3                   add    ebx,eax
   7:   eb f7                   jmp    0 <_start>
```

## Where to place data?
+ **imm**: Immediate Value 常數 
+ **reg**: Register 暫存器 
+ **mem**: Memory 記憶體 

## Immediate Value
+ Code 裡會看到的各種**常數**，例如 `mov eax, 0x1337`
+ 或者 code 裡看不到，但實際上 machine code 中會有一些固定值，例如 
`JE Label1` 實際上會是一個固定的 jump offset

## Register
+ `eax` `ebx` `ecx` `edx` - **DWORD** (32-bit)
+ `ax` `bx` `cx` `dx` - **WORD** (16-bit)
+ `ah` `bh` `ch` `dh` - **BYTE** (8-bit)
+ `al` `bl` `cl` `dl` - BYTE (8-bit)
+ 一般用途運算

<img style="border:none" src="images/reg.png">

## Register
+ `esp` `ebp` `esi` `edi` - DWORD (32-bit)
+ `sp` `bp` `si` `di` - WORD (16-bit) 很少用到 
+ \[esp, ebp\] 一般用來標記 stack frame 的範圍
+ esi, edi 常當做 buffer pointer 使用，而且某些字串指令會直接對 esi, edi 操作

## Other Register
+ `eip` - Program counter，即 code 執行到哪 (address)
+ `eflags` - 無法直接修改，但指令的執行結果會存放在此
+ `cs` `ss` `ds` `es` `fs` `gs` - segment register

## EFLAGS
+ Carry 
+ Parity
+ Auxiliary
+ Zero
+ Sign
+ Trap
+ Interrupt
+ Direction
+ Overflow


## Operation 
+ 常見 reg2reg, imm2reg, reg2mem, mem2reg
+ 不過 x86 指令集很複雜，基本上什麼都有
+ mov, add, sub, shl, shr, and, or, xor
+ push, pop

## MOV
+ Move imm/reg/mem value to reg/mem
+ `mov A, B` is "Move B to A" (A=B)
+ Data size 要相等

``` avrasm
mov eax, 0x1337
mov bx, ax
mov [esp+4], bl
```

## MOVZX / MOVSX
+ 從小的暫存器搬移資料到大的暫存器
+ Zero-extend / sign-extend
+ Example: `movzx ebx, al`

## More About Memory Access
+ `mov ebx, [esp + eax * 4]` Intel
+ `mov (%esp, %eax, 4), %ebx` AT & T
+ `mov BYTE [eax], 0x0f`<br>必須指定 data size: `BYTE/WORD/DWORD`

## Value?
`eax = 000000ff, esp: f0 00 00 00`

> + `mov eax, -1`
> + `mov al, -1`
> + `mov [esp], al`
> + `mov [esp], BYTE 3`
> + `movsx eax, BYTE [esp]`
> + `movsx eax, WORD [esp]`
> + `movsx DWORD [esp], al`

## ADD / SUB
+ 一般情況是 "reg += reg" 或 "reg += imm"
+ Data size 要相等

``` avrasm
add eax, ebx
sub eax, 123
sub eax, BL  ; Illegal
```

## SHL / SHR / SAR
+ Shift logical left / right
+ Shift arithmetic right
+ 計算 memory address 時常見 `SHL eax, 2` 

## Shift by variable
+ `shl eax, ebx` ?

## lea
+ `lea eax, [esp + 4]`
+ `lea eax, [eax + ebx*4 + 3]`


## Stack & PUSH / POP
+ Stack 是由 high address 開始，往 low address 長
+ `push eax` = `sub esp, 4` + `mov [esp], eax`
+ `pop eax` = `mov eax, [esp]` + `add esp, 4`
+ `push 0x1`

## Jump
+ Unconditional jump: `jmp`
+ Conditional jump: `je/jne`<br>另外還有 `ja/jae/jb/jbe/jg/jge/jl/jle` ...
+ 搭配 `cmp A, B` 使用，比較兩者的值並設定 eflags
+ Conditional jump 根據 eflags 的某些欄位決定要不要 jump，否則繼續跑下一條

## Example: jl for loop

``` avrasm
    mov ecx, 0
L1:

    ; Loop x 10 

    inc ecx
    cmp ecx, 10
    jl  L1

    ; followed instructions
```

## Compare jbe/jle
+ Below vs less ?
+ `ja/jae/jb/jbe` are unsigned comparison
+ `jg/jge/jl/jle` are signed comparison

## jmp offset
+ short 1-byte offset  `eb fe`
+ long 4-byte offset `e9 13 fc ff ff`

``` no-highlight
08048060 <_start>:
 8048060:       eb fe                   jmp    8048060 <_start>
 8048062:       eb 03                   jmp    8048067 <A>
 8048064:       90                      nop
 8048065:       90                      nop
 8048066:       90                      nop

08048067 <A>:
 8048067:       90                      nop
```


## rep
+ `rep/repe/repne`
+ `ins/movs/outs/lods/sots/scas/cmps`
+ `b/w/d`
+ Usage: `rep stosb`  (fill up buffer by `al`)
+ [Reference](http://faydoc.tripod.com/cpu/repne.htm)

## Example: strlen

+ Try `strlen()` and compile with `gcc -O1`

``` avrasm
mov ecx, -1
mov edi, msg
mov eax, 0    
repnz scasb   ; 找到字串結尾的 '\0' 
not ecx       ; ecx = -ecx - 1 = -1 - ecx = index of '\0' (1-based)
dec ecx       ; ecx = ecx - 1
```


# System Call

## System Call
+ Use `int 0x80` to call Linux system call
+ `eax` 指定 system call number
+ 參數放在 `ebx`, `ecx`, `edx`, `esi`, `edi`
+ 回傳值放在 `eax`
+ [Table](http://syscalls.kernelgrok.com/)

## Trace by strace

`strace /bin/echo AAAAA`

``` cpp
/* ... lots of syscall for loading binary ... */
write(1, "AAAAA\n", 6AAAAA
)                  = 6
close(1)                                = 0
munmap(0x7f8a54d91000, 4096)            = 0
close(2)                                = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```

## Example: Hello world

``` avrasm
section .text
global _start
_start:
    mov eax, 4    ; sys_write
    mov ebx, 1    ; fd
    mov ecx, msg  ; buf
    mov edx, 13   ; size
    int 0x80      ; write(1, "Hello world!\n", 13);

    mov eax, 1    ; sys_exit
    mov ebx, 0    ; status
    int 0x80      ; exit(0);
section .data
msg:
    db 'Hello world!', 0xA
```

## Some Useful System Call
+ `open/read/write`
+ `mmap/mprotect`
+ `execve`

## Open/read/write
<center>
 eax | ebx      | ecx | edx |  |
-----:|------:|-----:|-----:|:----|
 0x05| path | 0   | 0   | `open(path, O_RDONLY)` |
 0x03| fd | buf | size | `read(fd, buf, size)` |
 0x04| fd | buf | size | `write(fd, buf, size)` |

</center>

## mmap/mprotect
+ mmap: use to allocate an executable area
+ mprotect: disable data executable prevention

## execve
+ `execve(char* path, char* argv[], char* envp[]);`
+ path: 要執行的檔案路徑
+ argv: 參數的 char* pointer array
+ envp: environment variable 的 char* pointer array

## Example: launch a shell

``` avrasm
section .text
global _start
_start:
    mov eax, 0x0b
    mov ebx, sh
    mov ecx, argv
    mov edx, envp
    int 0x80

section .data
argv:
    dd sh, 0
envp:
    dd 0
sh:
    db "/bin/sh", 0
```

# Caller & Callee

## How to call a function?

+ `call` call a function by ...
    + Push **return address** on stack. Then jump to function.
+ `ret`
    + Pop return address on stack. Then jump by this value.

## Example: dummy function

``` avrasm
_start:
    ; start from here
    call foo
    ; return to here

foo:
    ; ... do someing here ...
    ret
```

## Calling Convention (呼叫慣例)
+ x86 沒有規定參數要怎麼傳!
    + By register
    + By stack


## Pass Arguments / Return Result
+ 參數依序放 stack
    + `mov [esp+X], Y`
    + 如果要用 `push` 則從最後一個參數開始
+ 回傳值放 `eax`

## Example : foo(1, 2, 3) => 3

```
_start:
    mov DWORD [esp], 1    ; arg1 = 1
    mov DWORD [esp+4], 2  ; arg2 = 2
    mov DWORD [esp+8], 3  ; arg3 = 3
    call foo

foo:
    mov ebx, [esp+4]      ; ebx = arg1 (there is a return value on stack!)
    mov eax, [esp+8]      ; eax = arg2
    add eax, ebx          ; result = arg1 + arg2
    ret

```

## More About Stack
+ Pass arguments
+ Save the return address
+ Save **local variable**

## Local Variable (區域變數)
+ Register 數量有限
+ 區域變數 (函式返回後就消失) 放在 stack frame 上
+ 用 `esp` 和 `ebp` 指出當前函式的 stack 範圍
+ 用 `esp` 或 `ebp` 相對位置存取: `mov eax, [esp+124]`
+ 很容易遞迴呼叫 (recursive call)

## Example: 1 + 2 + &hellip; + 10

``` avrasm
_start:
    push 10
    call sum_1_to_N
    nop

sum_1_to_N:
    push ebp
    mov  ebp, esp
    sub  esp, 4         ; prepare stack frame
    mov  eax, [ebp+8]
    test eax, eax       ; test if arg1 = 0
    jz   end            ; if arg1 = 0, then just end and return 0
    dec  eax
    mov  [esp], eax     
    call sum_1_to_N     ; eax = sum_1_to_N(arg1-1)
    mov  ebx, [ebp+8]   
    add  eax, ebx       ; result = eax + arg1
end:
    leave               ; ?
    ret
```

## Maintain Stack Frame
+ `sub esp, 4` ... `add esp, 4`
+ 用 `ebp` 保存前一個 frame 的 `esp`，`ebp` 本身則存到 stack 上，取回 `esp` 常見的有兩種方法
    + `mov esp, ebp` + `pop ebp`
    + `leave` (跟上個方法等價)

``` avrasm
    push ebp
    mov  ebp, esp
    sub  esp, 4
    ...

; (1)
    mov esp, ebp
    pop ebp
    ret
; (2)
    leave
    ret
```

# ELF executable

## file 

``` no-highlight
$ gcc a.c -o a -m32 && file ./a
a: ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), 
dynamically linked (uses shared libs), for GNU/Linux 2.6.24, 
BuildID[sha1]=312e8c1a9fab1d36b43b95c3c09b1cd8fe44b8ce, not stripped
```

+ ELF 32-bit LSB
+ Dynamically linked 

## Shared Library

``` no-highlight
$ ldd ./a
    linux-gate.so.1 =>  (0xf77a4000)
    libc.so.6 => /lib32/libc.so.6 (0xf75e8000)
    /lib/ld-linux.so.2 (0xf77a5000)
```

+ ELF 由 ld-linux.so.2 載入，負責 memory mapping，載入 shared library 等
+ 可以呼叫 libc.so.6 裡的 function

## Memory Layout of ELF File

+ Memory 以 page 為單位 (4096 bytes)，而且對齊

``` no-highlight
$ cat /proc/`pidof a`/maps
08048000-08049000 r-xp 00000000 fc:00 8678379    /home/course/temp/a
08049000-0804a000 r--p 00000000 fc:00 8678379    /home/course/temp/a
0804a000-0804b000 rw-p 00001000 fc:00 8678379    /home/course/temp/a
f7531000-f7532000 rw-p 00000000 00:00 0
f7532000-f76d8000 r-xp 00000000 fc:00 5374006    /lib32/libc-2.19.so
f76d8000-f76da000 r--p 001a5000 fc:00 5374006    /lib32/libc-2.19.so
f76da000-f76db000 rw-p 001a7000 fc:00 5374006    /lib32/libc-2.19.so
f76db000-f76df000 rw-p 00000000 00:00 0
f76ed000-f76ee000 rw-p 00000000 00:00 0
f76ee000-f76ef000 r-xp 00000000 00:00 0          [vdso]
f76ef000-f770f000 r-xp 00000000 fc:00 5374007    /lib32/ld-2.19.so
f770f000-f7710000 r--p 0001f000 fc:00 5374007    /lib32/ld-2.19.so
f7710000-f7711000 rw-p 00020000 fc:00 5374007    /lib32/ld-2.19.so
ff9eb000-ffa0c000 rw-p 00000000 00:00 0          [stack]
```

## readelf 
+ `readelf -a ./a`
+ 超多細節
+ Section offset: `.text` `.plt` `.got.plt` `.data` `.bss`
+ 檢查有沒有 DEP: `GNU_STACK RW`

## Call Shared Library Function
+ 執行時 (連library) 動態載入 <br>`dlopen()`, `dlsym()`, `dlclose()`
+ GOT - Global Offset Table

## Global Offset Table
+ 每次執行時 shared library 的 base address 可以不一樣 (ASLR)
+ GOT 中記錄每個 shared function 的正確 address
+ 第一次 function call 才會先進行 address 的計算，之後就是直接跳到該 address

## Example: puts()

``` no-highlight
080482f0 <puts@plt>:
 80482f0:       ff 25 0c a0 04 08       jmp    DWORD PTR ds:0x804a00c
 80482f6:       68 00 00 00 00          push   0x0     
 80482fb:       e9 e0 ff ff ff          jmp    80482e0 <_init+0x30> 
                                        ; go function loader
0804841d <main>:                        ; loader will update GOT entry
 ...
 8048426:       c7 04 24 d0 84 04 08    mov    DWORD PTR [esp],0x80484d0
 804842d:       e8 be fe ff ff          call   80482f0 <puts@plt>

0804a000 <_GLOBAL_OFFSET_TABLE_>:
 ...
 804a00c:       f6 82 04 08             ; 0x080482f6 = <puts@plt + 6>
```

+ 根據 memory 中位址 **0x804a00c** 的值，決定要跳哪
+ <span style="white-space: nowrap">第一次 `804842d`&#8594;`80482f0`**&#8594;**`80482f6`&#8594;`80482fb`&#8594;`loader()`</span>
+ 之後 `804842d`&#8594;`80482f0`**&#8594;**`puts()`

## Hook
+ 因為 shared function 是根據 **symbol name** 決定要載入哪一個，如果多個 
library 中有同名 function 的話，先 load 進來的優先
+ LD_PRELOAD - 指定在正常載入過程前要先載入的 library
+ 可以用來 hook 自訂的 function，蓋掉原本的功能

## Compile Shared Library
+ `gcc -o hook.so hook.c -fPIC -shared`

``` cpp
#include <stdio.h>
int strcmp(const char* str1, const char* str2) {
  printf("CMP [%s] [%s]\n", str1, str2);
  return 0; // 直接回傳相等
}
```

## Hook & Hijack 

``` no-highlight
$ cat login.c
...
    if (strcmp(input, password)==0) {
...
 
$ ./login
Input password: AAA
FAILED
$ LD_PRELOAD=./hook.so ./login
Input password: AAA
CMP [AAA] [password]
OK
```

## Security Issue
+ LD_PRELOAD 會造成安全上的問題
+ 因此有 effective user bit (-rwsr-xr-x) 使用 LD_PRELOAD 時，effective 會無效
+ 編譯時可以加上 -static 參數，這樣就不是 dynamically linked，也不能被 hook

## ltrace
+ 追踨有哪些 shared function 被呼叫

``` no-highlight
__libc_start_main(0x4005ed, 1, 0x7fffd3047048, 0x400640 <unfinished ...>
__isoc99_scanf(0x4006c4, 0x601080, 0x7fffd3047058, 0AAA
) = 1
strcmp("AAA", "password") = -47
puts("FAILED"FAILED
) = 7
+++ exited (status 0) +++
```

