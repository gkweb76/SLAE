# Title: Port to Shellcode converter
# File: port_converter.py
# Author: Guillaume Kaddouch
# SLAE-681

#!/usr/bin/python

import socket, sys

port = int(sys.argv[1])
network_order = socket.htons(port)
hex_converted = hex(network_order)

hex1 = hex_converted[2:4]
hex2 = hex_converted[4:6]

if hex1 == "":
    hex1 = "00"

if len(hex1) == 1:
    hex1 = "0" + hex1

if hex2 == "":
    hex2 = "00"

if len(hex2) == 1:
    hex2 = "0" + hex2

print "port %s" % str(port)
print "network order = %s" % str(network_order)
print "hexadecimal = %s" % hex_converted
print "shellcode format = \\x%s\\x%s" % (hex2, hex1)


