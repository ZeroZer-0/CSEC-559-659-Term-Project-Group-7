#!/usr/bin/env python3
# Functional test client for the lab FTP server. Not an exploit - this
# just exercises every command over normal-length input to prove the
# server works. Run the server first, then: python3 test_client.py
import socket, sys, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 2121


def recv_line(sock):
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace").rstrip("\n")


def main():
    s = socket.create_connection((HOST, PORT))
    print("banner:", recv_line(s))

    # HELP needs no login - plain text lines ending with a "." line
    s.sendall(b"HELP\n")
    print("help:")
    while True:
        line = recv_line(s)
        if line is None or line == ".":
            break
        print("   ", line)

    # VULN needs no login - same text-dump form
    s.sendall(b"VULN\n")
    print("vuln:")
    while True:
        line = recv_line(s)
        if line is None or line == ".":
            break
        print("   ", line)

    # needs login first
    s.sendall(b"SEARCH nope\n")
    print("search before login:", recv_line(s))

    s.sendall(b"LOGIN student student\n")
    print("login:", recv_line(s))

    s.sendall(b"CREATE alice hunter2\n")
    print("create:", recv_line(s))

    # upload a file (PUT = client sends a file to the server)
    payload = b"hello from the test client\n" * 3
    s.sendall(b'PUT "demo.txt" %d\n' % len(payload))
    print("put ready:", recv_line(s))
    s.sendall(payload)
    print("put result:", recv_line(s))

    # search for it
    s.sendall(b'SEARCH "demo.txt"\n')
    print("search:", recv_line(s))

    # list
    s.sendall(b"LIST\n")
    print("list:")
    while True:
        line = recv_line(s)
        if line == ".":
            break
        print("   ", line)

    # download it back (GET = server sends the file to us)
    s.sendall(b'GET "demo.txt"\n')
    hdr = recv_line(s)
    print("get header:", hdr)
    if hdr.startswith("OK "):
        size = int(hdr.split()[1])
        got = b""
        while len(got) < size:
            got += s.recv(size - len(got))
        ok = got == payload
        print("downloaded %d bytes, matches upload: %s" % (len(got), ok))

    s.sendall(b"EXIT\n")
    print("exit:", recv_line(s))
    s.close()


if __name__ == "__main__":
    main()
