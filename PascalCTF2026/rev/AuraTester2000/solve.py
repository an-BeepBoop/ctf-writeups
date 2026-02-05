#!/usr/bin/env python3
from pwn import *

# Copied from the translated source code
WORDS = ["tungtung","trallalero","filippo boschi","zaza","lakaka","gubbio","cucinato"]

def decode(encoded, steps):
    decoded = ""
    i = 0  
    j = 0 
    while j < len(encoded):
        if encoded[j] == " ":
            decoded += " "
            j += 1
            i += 1
            continue
        if i % steps == 0 and encoded[j].isdigit():
            num = ""
            while j < len(encoded) and encoded[j].isdigit():
                num += encoded[j]
                j += 1 decoded += chr(int(num))
            i += 1
        else:
            decoded += encoded[j]
            j += 1
            i += 1

    return decoded

def is_valid_phrase(phrase):
    parts = phrase.split(" ")
    return all(p in WORDS for p in parts)

io = remote("auratester.ctf.pascalctf.it", 7001)

io.recvuntil(b"> ")
io.sendline(b"sigma")


# We first need 500 aura the src code had values
# aura_values = [(150,-50), (-1000,50),(450,-80),(-100,50)]
# so optimally yes no yes no
io.recvuntil(b"> ")
io.sendline(b"1")
io.recvuntil(b"> ")
io.sendline(b"yes")
io.recvuntil(b"> ")
io.sendline(b"no")
io.recvuntil(b"> ")
io.sendline(b"yes")
io.recvuntil(b"> ")
io.sendline(b"no")

# Have enough to do the auratest
io.recvuntil(b"> ")
io.sendline(b"3")

# The encoded strings
line = io.recvline().decode()
encoded = line.split(": ", 1)[1].strip()

# brute force steps only (2,5) possible
decoded_phrase = None
for s in range(2, 6):
    attempt = decode(encoded, s)
    if is_valid_phrase(attempt):
        print(f"[+] Found valid decoded phrase with steps={s}: {attempt}")
        decoded_phrase = attempt
        break
if decoded_phrase is None:
    print("[-] Failed to decode phrase!")
    exit(1)

# send decoded phrase
io.recvuntil(b"> ")
io.sendline(decoded_phrase.encode())

# Should print the flag
io.interactive()
