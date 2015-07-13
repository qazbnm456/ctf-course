from sympy import *

p = randprime(2 ** 100, 2 ** 101)
q = randprime(2 ** 100, 2 ** 101)
n = p * q
e = 65537
m = int(open('flag').read().strip().encode('hex'), 16)
c = pow(m, e, n)
print "n =", n
print "e =", e
print "c =", c
