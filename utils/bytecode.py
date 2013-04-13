#!/usr/bin/python
# coding:  UTF-8
import sys, os, time

def usage():
    print """Usage: bytecode.py nasm_src_file

                    hj's utilite to fast compile
                    opcodes using nasm assembler

                    ********!!!!!!!!!!!!!********

                    Warrning: needed nasm on your
                             system!

                    ********!!!!!!!!!!!!!********"""

def shelltest(opcodes):
    ccode = """
/*shellcodetest.c*/ 
char code[] = "{}";\n""".format(opcodes)
    ccode += """int main(int argc, char **argv)
{
    int (*func)();
    func = (int (*)()) code;
    (int)(*func)();
}
""" 
    return ccode
    
def to_bytecode(filename):
    file = open(filename, 'rb').read()

    output = ''
    
    for ch in file:

        output += '\\x' + str(ch).encode('hex')

    return output

def nasm_compile(src):
    proc = os.popen('nasm -f bin -o {} {}'.format(src+'.bin', src)).read()
    if proc:
        print "Exception:\n" + proc
        sys.exit()
    time.sleep(3)
    bytecode = to_bytecode(src+'.bin')
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
    opcodes = bc('shellcode.asm', hdd=0)
    """

    if not os.path.exists(nasm_src):
        print "This file: {} not exist!".format(nasm_src)
        return False

    opcodes = nasm_compile(nasm_src)   
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
        usage()
        sys.exit()

    if len(sys.argv) == 2:
        rb = True
    elif sys.argv[2] == "nrb":
        rb = False
    else:
        rb = True

    if len(sys.argv) == 3:
        gc = True
    elif sys.argv[3] == "ngc":
        gc = False
    else:
        gc = True

    bc(sys.argv[1], rembin=rb, shctest=gc)
    sys.exit(0)

#genn ex-patt class