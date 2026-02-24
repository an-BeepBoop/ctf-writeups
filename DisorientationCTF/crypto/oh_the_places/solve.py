#!/usr/bin/env python3
from pwn import *

KEY_LEN = 16

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

r = remote("chals.disorientation.cssa.club", 9056)

# Parse the flag line
r.recvuntil(b"FLAG: ")
flag_line = r.recvline().strip()

# The flag is printed as raw bytes 
cipher_flag = eval(flag_line.decode())
print(f"Encrypted flag: {cipher_flag}")

# Recover KEY with a known PT -> CT pair
known_plain = b"A" * KEY_LEN
r.sendlineafter(b"Enter a string to encrypt: ", known_plain)
response = r.recvline()
cipher_known = eval(response.split(b"==>")[1].strip().decode())
key = xor(cipher_known, known_plain)
print(f"Recovered key: {key}")

# Decrypt flag
key_repeated = (key * ((len(cipher_flag) // KEY_LEN) + 1))[:len(cipher_flag)]
flag = xor(cipher_flag, key_repeated)

print(f"Flag: {flag.decode()}")
r.close()
