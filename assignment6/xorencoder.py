#!/usr/bin/python

# Title: XOR encoder
# File: xorencoder.py
# Author: Guillaume Kaddouch
# SLAE-681

import sys

shellcode = (
"\x77\x6f\x6e"

#push dword 0x6e776f64           ; = 'down'
#"\x6e\x77\x6f\x64"

#push dword 0x74756873           ; = 'shut'
#"\x74\x75\x68\x73"

#push dword 0x2f6e6962           ; = '/nib'
#"\x2f\x6e\x69\x62"

#push word 0x732f      
#"\x73\x2f"
)

xor_key = 0xAA

encoded = ""
encoded2 = ""

print "[*] Encoding shellcode..."

for x in bytearray(shellcode):
    # XOR encoding
    y = x^xor_key
    encoded += '\\x'
    encoded += '%02x' % y

    encoded2 += '0x'
    encoded2 += '%02x,' %y

print "hex version : %s" % encoded
print ""
print "nasm version : %s" % encoded2
print ""
print 'Len: %d' % len(bytearray(shellcode))
