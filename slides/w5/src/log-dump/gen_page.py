#!/usr/bin/env python2
import sys
import re
import json
import subprocess

binary = sys.argv[1]
log = sys.argv[1]
js = open('log.js','w')

dump = subprocess.check_output('objdump -M intel --no-show-raw-insn -d %s'%binary, shell=True)
symbol = ''
symbol_addr = 0
inst_tb = {}
for line in dump.split('\n'):
  line = line.strip()
  if len(line)==0:
    continue
  if re.match('^[0-9a-f]+ <', line):
    symbol_addr, symbol = re.findall('^([0-9a-f]+) <(.*)>:', line)[0]
    symbol_addr = int(symbol_addr,16)
  elif re.match('^[0-9a-f]+:', line):
    x = int(re.findall('^([0-9a-f]+):', line)[0],16)
    if x==symbol_addr:
      addr = symbol
    else:
      addr = symbol+'+'+str(x-symbol_addr)
    inst = line[line.find(':')+1:].strip()
    inst_tb[x] = ('%s <%s>'%(hex(x),addr),inst)

with open(log+".log") as f:
  states = []
  f.readline()
  pc = 0
  while True:
    state = {}
    # instruction
    asm = f.readline()[3:-1]
    x = int(re.findall('0x([0-9a-f]+)',asm)[0],16)
    if x not in inst_tb:
      tp = asm.find(':')
      inst_tb[x] = (asm[:tp], asm[tp+1:].strip())

    # registers
    state['regs'] = {}
    for i in range(16):
      x = f.readline().split()
      state['regs'][x[0]] = int(x[1],16)
    # memory dump
    state['memory'] = {}
    while True:
      cmd = f.readline()[:-1]
      if cmd=='' or cmd[:4]=='Dump':
        break
      size, addr = re.findall('x/([0-9]+)wx (.*)', cmd)[0]
      size = int(size)
      if addr.find('$esp')==-1:
        addr = hex(int(addr))
      values = []
      for i in range((size+3)/4):
        y = f.readline()
        for x in y[y.find(':')+1:].split():
          values.append(int(x,16))
      if addr.find('$esp')!=-1:
        state['stack'] = values
      else:
        state['memory'][addr] = values
    #finalize
    states.append(state)
    pc += 1
    if cmd=='':
      break

  ntb = {}
  for i in range(len(states)-1, -1, -1):
    state = states[i]
    x = state['regs']['eip']
    ntb[x] = i
    opcode = inst_tb[x][1]
    states[i]['rni'] = i-1
    if opcode.find('call')!=-1:
      y = states[i+1]['stack'][10]
      if y not in ntb:
        states[i]['ni'] = -1
      else:
        states[i]['ni'] = ntb[y]
        states[ntb[y]]['rni'] = i
    else:
      if i==len(states)-1:
        states[i]['ni'] = -1
      else:
        states[i]['ni'] = i+1
    if opcode.find('ret')!=-1:
      if i==len(states)-1:
        states[i]['fin'] = -1
      else:
        states[i]['fin'] = i+1
    else:
      if states[i]['ni']==-1:
        states[i]['fin'] = -1
      else:
        states[i]['fin'] = states[states[i]['ni']]['fin']
  p = -1
  for i in range(len(states)):
    state = states[i]
    x = state['regs']['eip']
    states[i]['pret'] = p
    if inst_tb[x][1].find('ret')!=-1:
      p = i
  p = -1
  for i in range(len(states)-1, -1, -1):
    state = states[i]
    x = state['regs']['eip']
    states[i]['nret'] = p
    if inst_tb[x][1].find('ret')!=-1:
      p = i



js.write('states='+json.dumps(states)+';\n')

inst_r = {}
inst_list = []
sr = sorted(inst_tb, key=inst_tb.get)
for i in range(len(sr)):
  inst_r[sr[i]] = i
  inst_list.append(inst_tb[sr[i]])

js.write('inst_a2i='+json.dumps(inst_r)+';\n')
js.write('inst_i2c='+json.dumps(inst_list)+';\n')
js.close()

