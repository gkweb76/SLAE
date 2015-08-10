# Title: ASM to Shellcode converter
# File: asm2shellcode.sh
# Author: Guillaume Kaddouch
# SLAE-681

#!/bin/bash
clear

file=$1
steps="5"

if [ -z $file ]; then
        echo "[-] No argument given, exiting."
        exit
fi

extension=`echo $file | grep '.asm'`

if [ ! -z $extension ]; then
	echo "[!] Extension specified, please remove it."
	exit
fi

if [ ! -e $file.asm ]; then
	echo "[-] "$1".asm file does not exist."
	exit
fi

echo '[*] 1/'$steps': Assembling "'$file'.asm" with Nasm ... '
echo "nasm -f elf32 -o "$file".o "$file".asm"
nasm -f elf32 -o $file.o $file.asm
echo ""

if [ -z $file.o ]; then
	echo "[-] Error while assembling, "$file".o not created"
	exit
fi

echo '[+] 2/'$steps': Linking ...'
echo "ld -o "$file" "$file".o"
ld -o $file $file.o
echo ""

if [ -z $file ]; then
        echo "[-] Error while linking, "$file" not created"
        exit
fi


echo '[+] 3/'$steps': Converting to shellcode'
echo "objdump -d "$file
objdump -d $file | grep '[0-9a-f]:' | grep -v 'file' | grep -v 'fichier' | cut -f2 -d':' | cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/g' > ./.tmp
shellcode=`cat ./.tmp`
echo $shellcode
rm ./.tmp
NULL=`echo $shellcode | grep -i '\x00'`
x0A=`echo $shellcode | grep -i '\x0a'`
x0D=`echo $shellcode | grep -i '\x0d'`

if [ ! -z $NULL ]; then
	echo "[!] >>>>>>>>>>> NULL bytes detected!"
	exit
fi

if [ ! -z $x0A ]; then
        echo "[!] >>>>>>>>>>> \x0A bytes detected!"
fi

if [ ! -z $x0D ]; then
        echo "[!] >>>>>>>>>>> \x0D bytes detected!"
fi

echo ""

if [ -z $shellcode ]; then
        echo "[-] Error while converting to shellcode (empty)."
        exit
fi


echo '[*] 4/'$steps': Creating shellcode-'$file'.c'
cfile="./shellcode-"$file".c"
cat ./shell1.c > $cfile
echo $shellcode';' >> $cfile
cat ./shell2.c >> $cfile

if [ -z $cfile.c ]; then
        echo "[-] Error while creating C file, "$cfile" not created"
        exit
fi


#cat $cfile
echo ""

echo '[*] 5/'$steps': Compiling C file...'
echo "gcc -fno-stack-protector -z execstack "$cfile" -o ./shellcode-"$file
gcc -fno-stack-protector -z execstack $cfile -o ./shellcode-$file

if [ -z shellcode-$cfile ]; then
        echo "[-] Error while compiling, shellcode-"$cfile" not created"
        exit
fi


chmod +x ./shellcode-$file

echo '[*] Done!'
