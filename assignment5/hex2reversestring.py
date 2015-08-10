#!/usr/bin/python

# Convert shellcode hex input as string
# Author: Guillaume Kaddouch
# SLAE-681

import sys

try:
    if sys.argv[1]:
        arg1 = sys.argv[1]
        string = arg1

    if sys.argv[2] == "null":
        string += '\n'
except:
    toto = "Nothing"
finally:

    encode = string.decode('hex')

print 'string = %s' % string
print 'encode = %s' % encode
