# vulnFTP

A deliberately vulnerable, simplified FTP-style server written in C. It has three intentional buffer overflows, each in its own Visual Studio project with the mitigations set up to make that technique the point.

CSEC 559/659 project. Lab use only, do not run outside a VM.

## Group Members

- Jared Laliberte, jnl1479@rit.edu
- Willis Martin, wrm3207@rit.edu
- Josh Waltman, jdw7334@rit.edu

## Layout

Three folders, each a separate Visual Studio project. The server source is roughly the same in all three; what changes is the project's protection settings so each overflow is exploitable as intended.

| Folder | Vuln | Where | Project settings |
|---|---|---|---|
| `Simple Overflow` | plain stack overflow (jmp esp) | `search` filename | /GS off, DEP off, ASLR off |
| `SEH` | SEH overwrite | `login` username | /GS off, SafeSEH off, DEP off, ASLR off |
| `DEP` | DEP bypass via VirtualProtect ROP | `put` file path | /GS off, SafeSEH off, ASLR off, DEP **on** |

`essfunc.dll` ships next to each server. It loads at a fixed base (0x62500000, no ASLR) and provides the jmp esp / pop-pop-ret / ROP gadgets.

## Setup

1. Open the `vulnFTP.sln` in the folder you want (VS 2022).
2. Build **Release | x86** (Rebuild, not Build). Protections are already set per the table above.
3. Make sure `essfunc.dll` is in the same directory as the built `.exe` (it already is in the project and output folders).
4. Run the server. It listens on port 2121 by default (`vulnFTP.exe [port]`). Default account: `student` / `student`.

## python tools

Each folder has a `python tools` directory:

- `client.py` / `test_client.py` - interact with and test the normal FTP functionality.
- `X_pattern.py` - sends a pattern to find the offset for that stage.
- `X_exploit.py` - delivers the payload for that stage. (`Simple Overflow` has both `windows_` and `linux_` pattern/exploit scripts.)

These worked for us but may need tweaking for your environment: set the target `HOST`, drop in your own msfvenom shellcode, and re-confirm the offset with the pattern script if your build differs. Bad chars for every stage are `\x00 \x0a \x0d \x22`.

## Commands

All except `login`, `create`, `help`, `vuln` require authentication.

- `login "user" "pass"` - log in. **SEH overflow on username.**
- `create "user" "pass"` - make an account.
- `search "name"` - report if a file exists and its size. **Simple overflow on name.**
- `put "path" size` - upload a file to the server. **DEP-bypass overflow on path.**
- `get "name" "path"` - download a server file to the client.
- `list` - list files on the server.
- `help` - usage info.
- `vuln` - where/how the service is vulnerable.
