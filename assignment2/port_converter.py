#!/usr/bin/python

import socket, sys

port = int(sys.argv[2])
address = str(sys.argv[1]).split('.')

ip = ""
for byte in address:
    ip += "\\x" + str(hex(int(byte)))[2:]


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

print "address = %s -> %s" % (str(sys.argv[1]), ip)
print "port = %s -> \\x%s\\x%s" % (str(port), hex2, hex1)



