#!/usr/bin/env python3
import socket, sys, shlex, os

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 2121

USAGE = """commands:
  login <user> <pass>
  create <user> <pass>
  search <name>
  list
  put <localpath>                upload a local file (stored under its basename)
  get <servername> <localpath>   download a server file to your machine
  help                           show the server's help text
  vuln                           show the intentional vulnerabilities
  exit | quit
  ?                              show this list
local paths are relative to your current directory; use forward slashes."""


def recv_line(sock):
    data = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            return data.decode(errors="replace").rstrip("\r") if data else None
        if b == b"\n":
            return data.decode(errors="replace").rstrip("\r")
        data += b


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def do_put(sock, args):
    if len(args) < 1:
        print("usage: put <localpath>")
        return
    localpath = args[0]
    storename = os.path.basename(localpath)
    try:
        with open(localpath, "rb") as f:
            data = f.read()
    except OSError as e:
        print("local file error:", e)
        return
    sock.sendall(('PUT "%s" %d\n' % (storename, len(data))).encode())
    resp = recv_line(sock)
    if resp != "READY":
        print("server:", resp)
        return
    sock.sendall(data)
    print("server:", recv_line(sock),
          "(%d bytes sent, stored as '%s')" % (len(data), storename))


def do_get(sock, args):
    if len(args) < 2:
        print("usage: get <servername> <localpath>")
        return
    remotename, localpath = args[0], args[1]
    sock.sendall(('GET "%s"\n' % remotename).encode())
    hdr = recv_line(sock)
    if hdr is None:
        print("connection closed")
        return
    if not hdr.startswith("OK "):
        print("server:", hdr)
        return
    size = int(hdr.split()[1])
    data = recv_exact(sock, size)
    try:
        with open(localpath, "wb") as f:
            f.write(data)
    except OSError as e:
        print("local write error:", e)
        return
    print("saved %d bytes to %s" % (len(data), localpath))


def do_list(sock):
    sock.sendall(b"LIST\n")
    line = recv_line(sock)
    if line is None:
        return
    if line.startswith("ERR") or line == "(empty)":
        print("server:", line)
        return
    while line is not None and line != ".":
        print("  ", line)
        line = recv_line(sock)


def do_textdump(sock, cmd):
    sock.sendall((cmd + "\n").encode())
    while True:
        line = recv_line(sock)
        if line is None or line == ".":
            break
        print(line)


def send_line_cmd(sock, text):
    sock.sendall((text + "\n").encode())
    print("server:", recv_line(sock))


def main():
    s = socket.create_connection((HOST, PORT))
    print(recv_line(s))
    print(USAGE)
    try:
        for raw in sys.stdin:
            raw = raw.strip()
            if not raw:
                continue
            try:
                parts = shlex.split(raw)
            except ValueError as e:
                print("parse error:", e)
                continue
            if not parts:
                continue
            cmd, rest = parts[0].lower(), parts[1:]

            if cmd == "?":
                print(USAGE)
            elif cmd == "put":
                do_put(s, rest)
            elif cmd == "get":
                do_get(s, rest)
            elif cmd == "list":
                do_list(s)
            elif cmd == "help":
                do_textdump(s, "HELP")
            elif cmd == "vuln":
                do_textdump(s, "VULN")
            elif cmd == "search":
                send_line_cmd(s, 'SEARCH "%s"' % (rest[0] if rest else ""))
            elif cmd == "login":
                if len(rest) < 2:
                    print("usage: login <user> <pass>")
                else:
                    send_line_cmd(s, "LOGIN %s %s" % (rest[0], rest[1]))
            elif cmd == "create":
                if len(rest) < 2:
                    print("usage: create <user> <pass>")
                else:
                    send_line_cmd(s, "CREATE %s %s" % (rest[0], rest[1]))
            elif cmd in ("exit", "quit"):
                send_line_cmd(s, "EXIT")
                break
            else:
                send_line_cmd(s, raw)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()


if __name__ == "__main__":
    main()
