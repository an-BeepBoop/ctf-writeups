#!/usr/bin/env python3
import numpy as np

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

def gf2_matvec(A, v):
    return list(A @ np.array(v) % 2)

def int_to_bits(n, width=32):
    return [(n >> (width - 1 - i)) & 1 for i in range(width)]

def bits_to_int(bits):
    result = 0
    for b in bits:
        result = (result << 1) | int(b)
    return result

def gf2_rank(M):
    temp = M.copy() % 2
    rank = 0
    rows, cols = temp.shape
    for col in range(cols):
        pivot = -1
        for row in range(rank, rows):
            if temp[row, col] == 1:
                pivot = row
                break
        if pivot == -1:
            continue
        temp[[rank, pivot]] = temp[[pivot, rank]]
        for row in range(rows):
            if row != rank and temp[row, col] == 1:
                temp[row] ^= temp[rank]
        rank += 1
    return rank

# Load known plaintext-ciphertext pairs
with open("pt.bin", "rb") as f:
    pt_raw = f.read()
with open("ct.enc", "rb") as f:
    ct_raw = f.read()

n_blocks = len(pt_raw) // 4
pt_blocks = [int.from_bytes(pt_raw[i*4:(i+1)*4], 'big') for i in range(n_blocks)]
ct_blocks = [int.from_bytes(ct_raw[i*4:(i+1)*4], 'big') for i in range(n_blocks)]

# Build bit-vector matrices P and C (columns = block vectors)
P = np.zeros((32, n_blocks), dtype=int)
C = np.zeros((32, n_blocks), dtype=int)
for i in range(n_blocks):
    P[:, i] = int_to_bits(pt_blocks[i])
    C[:, i] = int_to_bits(ct_blocks[i])

# Select 32 linearly independent columns from P and C
selected = []
current_rank = 0
P_sel = np.zeros((32, 0), dtype=int)
for i in range(n_blocks):
    candidate = np.concatenate([P_sel, P[:, i:i+1]], axis=1)
    r = gf2_rank(candidate)
    if r > current_rank:
        selected.append(i)
        current_rank = r
        P_sel = candidate
        if current_rank == 32:
            break
if current_rank < 32:
    raise ValueError(f"Could not find 32 linearly independent plaintexts! Only got rank {current_rank}")

P32 = P[:, selected]
C32 = C[:, selected]
P32_inv = gf2_inverse(P32)

# C = A * P, so A = C * P^-1
A = C32 @ P32_inv % 2

# Verify A against all known pairs
for i in range(n_blocks):
    if list(A @ P[:, i] % 2) != list(C[:, i]):
        raise ValueError(f"Matrix A failed verification at block {i}!")
print(f"Matrix A recovered and verified using {n_blocks} known plaintext-ciphertext pairs")

# Decrypt the flag
A_inv = gf2_inverse(A)

with open("flag.enc", "rb") as f:
    flag_raw = f.read()

flag_blocks = [int.from_bytes(flag_raw[i*4:(i+1)*4], 'big') for i in range(len(flag_raw) // 4)]

plaintext = b""
for block in flag_blocks:
    c_bits = int_to_bits(block)
    p_bits = gf2_matvec(A_inv, c_bits)
    plaintext += bits_to_int(p_bits).to_bytes(4, 'big')

print(f"Flag: {plaintext.decode()}")
