#!/usr/bin/python

# Title: ELF to Metasploit converter
# Author: Guillaume Kaddouch
# SLAE-681

import sys, os

try:
    file = sys.argv[1]
except:
    print "you must submit a filename."
    exit()

os.system("objdump -d " + file + " -M intel > ./tmp")

p = open(file + ".payload", "w")
with open("./tmp", "r") as f:
    for line in f:
        r = line.split('\t')
        converted = ""

        if len(r) == 3:
            opcode = r[1].replace(" ", "")
            asm = r[2].replace("   ", " ")
            asm.replace("  ", " ")
            asm = asm[:-1]

            index = 0
            while index < len(opcode):
                converted += "\\x" + opcode[index:index+2]
                index = index + 2

            converted = '  \t    "' + converted + '"' + ' ' * (40 - len(converted))
            buffer = converted + '+#   ' + asm 
            print buffer
            p.write(buffer + '\n')
f.close()
p.close()

