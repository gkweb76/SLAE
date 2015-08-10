#!/usr/bin/python

# Convert ndisasm output into a format suitable for a Metasploit module
# Author: Guillaume Kaddouch
# SLAE-681

import sys, os

try:
    file = sys.argv[1]
except:
    print "you must submit a filename."
    exit()

p = open(file + ".payload", "w")
with open(file, "r") as f:
    for line in f:
        r = line.split('\t')
        converted = ""        
        print r
        if len(r) == 3:
            opcode = r[1].replace(" ", "")
            asm = r[2].replace("   ", " ")
            asm.replace("  ", " ")
            asm = asm[:-1]
            for index in range(len(opcode)/2):
                converted += "\\x" + opcode[index:index+2]
            converted = '  \t    "' + converted + '"' + ' ' * (40 - len(converted))
            buffer = '\t' + asm 
            print buffer
            p.write(buffer + '\n')
f.close()
p.close()
