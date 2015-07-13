#!/usr/bin/env python

import re
from pwn import *

context(arch='i386')
s = open('./bin100').read()
sl = list(s)

for d in re.finditer('[\x83][\x7C][\x24][\x50][\x01-\x07]', s):
  x = s[d.start():d.start()+20]
  tcmp, tjne = disasm(x).split('\n')[:2]
  print tcmp
  print tjne
  if '0f 85' in tjne:
    sl[d.start()+6] = '\x84'
  else:
    sl[d.start()+5] = '\x74'

open('./bin100-patched', 'wb').write(''.join(sl))
