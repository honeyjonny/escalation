#!/usr/bin/python
# coding:  UTF-8
import sys, os, time, optparse

usage = """Usage: bytecode.py <nasm_src_file> [--nrb] [--ngc] [-h | --help]

                    hj's utilite to fast compile
                    opcodes using nasm assembler

                    ********!!!!!!!!!!!!!********

                    Warrning: needed nasm on your
                             system!

                    ********!!!!!!!!!!!!!********"""

def shelltest(opcodes):
    ccode = """
/*shellcodetest.c*/
#include <string.h>
char code[] = "{}";\n""".format(opcodes)
    ccode += """int main(int argc, char **argv)
{
    (*(void  (*)()) code)();
}
""" 
    return ccode
    
def to_bytecode(filename, hdd):
    file = open(filename, 'rb').read()

    if not hdd:
        return file

    output = ''
    
    for ch in file:

        output += '\\x' + str(ch).encode('hex')

    return output

def nasm_compile(src, hdd):
    proc = os.popen('nasm -f bin -o {} {}'.format(src+'.bin', src)).read()
    if proc:
        print "Exception:\n" + proc
        sys.exit()
    time.sleep(3)
    bytecode = to_bytecode(src+'.bin', hdd)
    return bytecode

def bc(nasm_src, hdd=True, rembin=True, shctest=True):
    """
    hj's utilite to fast compile
    opcodes using nasm assembler

    ********!!!!!!!!!!!!!********

    Warning: needed nasm on your
              system!

    ********!!!!!!!!!!!!!********

    hdd - is opcodes places on harddisk
    rembin - is compiled nasm binary be removed
    shctest - is be generated special c-src 
              to compile it and test shellcode work

    if you set hdd == 0 - func returned opcodes to you
    opcodes = bc('./shellcode.asm', hdd=0)
    """

    if not os.path.exists(nasm_src):
        print "This file: {} not exist!".format(nasm_src)
        return False

    opcodes = nasm_compile(nasm_src, hdd)   
    if hdd:
        print >> open(nasm_src+'_bc.txt','wb'), opcodes
        if shctest:
            print >> open(nasm_src+'_shct.c','wb'), shelltest(opcodes)
        if rembin:
            os.remove(nasm_src+'.bin')
        print 'ok :)'
        sys.exit()
    elif rembin:
        os.remove(nasm_src+'.bin')

    return opcodes

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print usage
        sys.exit(0)

    p = optparse.OptionParser()
    p.set_usage(usage)
    p.add_option('--nrb', action="store_false", dest="rb", help="not remove compiled binary file")
    p.add_option('--ngc', action="store_false",dest="gc", help="not generate c-proof source code")
    p.set_defaults(rb=True,gc=True)
    opt, args = p.parse_args()

    bc(sys.argv[1], rembin=opt.rb, shctest=opt.gc)
    sys.exit(0)

#EOF
