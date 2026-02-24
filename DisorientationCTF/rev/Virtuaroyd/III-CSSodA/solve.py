#!/usr/bin/env python3
from pwn import *
import re

MASK = (1 << 64) - 1
TARGET = 67_83_83_65_2026

def unxorshift_left(val, shift):
    res = val
    for _ in range(6):
        res = val ^ ((res << shift) & MASK)
    return res & MASK

def unxorshift_right(val, shift):
    res = val
    for _ in range(6):
        res = val ^ (res >> shift)
    return res & MASK

def inverse_shuffle(rng):
    rng = unxorshift_left(rng, 28)
    rng = unxorshift_right(rng, 13)
    rng = unxorshift_left(rng, 15)
    return rng


# ------------- Copied from stage2 (helpers to recover RNG) ---------
def get_counts(show_output):
    hex_vals = re.findall(r'\((0x[0-9a-fA-F]+)\)', show_output)
    counts = [int(x, 16) for x in hex_vals[:16]]
    return counts

def reconstruct_rng(counts):
    rng = 0
    for i in range(16):
        rng |= (counts[i] << (4 * i))
    return rng

r = remote("chals.disorientation.cssa.club", 4670)
r.recvuntil(b"> ")

# Recover initial RNG value
r.sendline(b"show")
show_output = r.recvuntil(b"> ").decode()
counts = get_counts(show_output)
rng_current = reconstruct_rng(counts)
print(f"Current RNG: {rng_current}")

# Compute the required RNG value before 26 shuffles + shake
rng_needed = TARGET
for _ in range(26):
    rng_needed = inverse_shuffle(rng_needed)
shake_val = rng_current ^ rng_needed # invert the shake()
print(f"Shake value: {shake_val}")

# Shake!
r.sendline(f"shake {shake_val}".encode())
r.recvuntil(b"> ")

# Buy and Insert
# insert_money(r, 2.00)
r.sendline(b"insert $2")
r.sendline(b"buy C 4")

result = r.recvall(timeout=2).decode()
print(result)
