#!/usr/bin/python

# Convert string input to shellcode hex
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

    reverse = string[::-1]
    encode = reverse.encode('hex')

print 'string = %s' % string
print 'reverse = %s' % reverse
print 'encode = %s' % encode
