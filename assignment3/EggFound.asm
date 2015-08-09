; Title: Shellcode printing "Egg Found!!"
; Author: Guillaume Kaddouch
; SLAE-681


global _start

section .text

_start:

	jmp short get_address

shellcode:
	pop ecx

	xor eax, eax
	push eax		; prepare stack for string copy (NULL terminated)
	mov al, 0x4		; write syscall code

	xor ebx, ebx
	mov bl, 0x1		; 1st arg: stdout

	;mov ecx, edx		; 2nd arg: pointer to message

	xor edx, edx
	mov dl, 12		; 3rd arg: message length
	int 0X80		; write syscall

	xor eax, eax
	mov al, 0x1		; exit syscall code
	int 0x80		; exit syscall

get_address:
	call shellcode
	message db "Egg Found!!", 0xA
