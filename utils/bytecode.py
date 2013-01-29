import sys, os, time

def usage():
    print """Usage: bytecode.py nasm_src_file

                    hj's utilite to fast compile
                    opcodes using nasm assembler

                    Warring: needed nasm on your
                             system!"""
    
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

def main():
    if len(sys.argv) < 2:
        usage()
        sys.exit()

    if not os.path.exists(sys.argv[1]):
        print "This file: {} not exist!".format(sys.argv[1])
        sys.exit()
    
    opcodes = nasm_compile(sys.argv[1])   
    print >> open(sys.argv[1]+'_bc.txt','wb'), opcodes
    os.remove(sys.argv[1]+'.bin')
    print 'ok :)'
    sys.exit()

main()
