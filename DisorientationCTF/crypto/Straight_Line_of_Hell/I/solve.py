#!/usr/bin/env python3
from pwn import *
import numpy as np

r = remote("chals.disorientation.cssa.club", 4589)
r.recvrepeat(0.5)  # Receives past the banner

def encrypt(plaintext):
    msg = f"0x{plaintext:08x}".encode()
    r.sendline(msg)
    ciphertext = r.recvline().decode()
    return int(ciphertext.strip(), 16)

# Copied from script.py
def gf2_inverse(p_0):
    local_0 = p_0.shape[0]
    local_1 = p_0.copy() % 2
    local_2 = np.identity(local_0, dtype=int)
    local_3 = np.concatenate((local_1, local_2), axis=1)
    for local_4 in range(local_0):
        local_5 = -1
        for local_6 in range(local_4, local_0):
            if local_3[local_6, local_4] == 1:
                local_5 = local_6
                break
        if local_5 == -1:
            raise ValueError("?????")
        if local_5 != local_4:
            local_3[[local_4, local_5]] = local_3[[local_5, local_4]]
        for local_6 in range(local_0):
            if local_6 != local_4 and local_3[local_6, local_4] == 1:
                local_3[local_6] ^= local_3[local_4]
    return local_3[:, local_0:]

# Computes the result of A * v in GF(2)
def gf2_matvec(A, v):
    return list(A @ v % 2)

def int_to_bits(n, width=32):
    return [(n >> (width - 1 - i)) & 1 for i in range(width)]

def bits_to_int(bits):
    result = 0
    for b in bits:
        result = (result << 1) | b
    return result

# Recover matrix A with basis vectors
A = np.zeros((32, 32), dtype=int)
for i in range(32):
    unit = 1 << (31 - i)
    col = int_to_bits(encrypt(unit))
    for j in range(32):
        A[j][i] = col[j]

# Decrypt the flag using the inverse
with open("flag.txt", "r") as f:
    blocks = f.read().strip().split()

A_inv = gf2_inverse(A)
plaintext = b""
for block in blocks:
    c_bits = int_to_bits(int(block, 16))
    p_bits = gf2_matvec(A_inv, c_bits)
    plaintext += int(bits_to_int(p_bits)).to_bytes(4, 'big')

print(plaintext.decode())
r.close()
