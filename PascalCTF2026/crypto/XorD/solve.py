#!/usr/bin/env python
import random

def xor(a, b):
    return bytes([a ^ b])

with open('output.txt', 'r') as f:
    encrypted_hex = f.read()

encrypted_bytes = bytes.fromhex(encrypted_hex)

random.seed(1337)
decrypted_flag = b''

for b in encrypted_bytes:
    random_key = random.randint(0, 255)
    decrypted_flag += xor(b, random_key)

print(decrypted_flag)
