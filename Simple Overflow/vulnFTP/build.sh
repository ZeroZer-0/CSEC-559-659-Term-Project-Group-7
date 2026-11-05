#!/bin/sh
# Windows 32-bit build, modeled on the teacher's build.sh.
# Produces essfunc.dll + server.exe with fixed image bases and ASLR off.
# You still handle DEP + global ASLR + optimization toggles on the VM.
set -e

CC=i686-w64-mingw32-gcc

# --- gadget DLL: fixed base 0x62500000, no dynamicbase (no ASLR) ---
$CC -c essfunc.c -o essfunc.o -fno-stack-protector

$CC -shared \
    -o essfunc.dll \
    -Wl,--out-implib=libessfunc.a \
    -Wl,--image-base=0x62500000 \
    -Wl,--disable-dynamicbase \
    essfunc.o

# --- server: fixed base 0x51700000, no dynamicbase, links the DLL ---
$CC \
    server.c parser.c handlers.c compat.c \
    -o server.exe \
    -fno-stack-protector \
    -Wl,--image-base=0x51700000 \
    -Wl,--disable-dynamicbase \
    -lws2_32 \
    ./libessfunc.a

echo "built: essfunc.dll server.exe (32-bit, ASLR off)"
