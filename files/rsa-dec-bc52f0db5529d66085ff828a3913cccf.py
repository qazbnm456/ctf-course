import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

n = 29483112906907846550407371381907804051925957834404110624325531950200215274674279351500117069061279396866776918114198748748643519779529947303729199772247349
e = 65537
d = int(open('private_key').read())
c = int(raw_input())
m = pow(c, d, n)

if m == int(open('flag').read().strip().encode('hex'), 16):
    print 'I will not decrypt the flag for you @_@'
else:
    print m
