import yaml

gdb.execute('target remote localhost:4444', False, True)
gdb.execute('b main', False, True)
gdb.execute('c', False, True)

class LogDump (gdb.Command):

  def __init__ (self):
    super (LogDump, self).__init__ ("log-dump", gdb.COMMAND_USER)

  def invoke (self, arg, from_tty):
    name = arg
    f = open(name+'.log','w')
    config = yaml.load(file(name+'.yaml','r'))
    watch = config['watch']
    while True:
      s = 'Dump\n'
      s += gdb.execute('x/i $eip', False, True)
      s += gdb.execute('info registers', False, True)
      for x in watch:
        cmd = 'x/%dwx %s' % (x['size'], str(x['address']))
        s += cmd+'\n'
        s += gdb.execute(cmd, False, True)
      f.write(s)
      f.flush()
      gdb.execute('si', False, True)

LogDump()
