import sys

def usage():
	print """Usage: exp.py <name_to_patt.py>"""

if len(sys.argv) < 2:
	usage()
	sys.exit()

patt = '' + \
"""#!/usr/bin/python
# coding: UTF-8

from socket import *
import struct, shellgen

junk = 0

exp = ''

ret = struct.pack('<I',  0)


s = socket(AF_INET, SOCK_STREAM)
s.connect(('', 0))"""

print >> open(sys.argv[1], 'wb'), patt
sys.exit(0)