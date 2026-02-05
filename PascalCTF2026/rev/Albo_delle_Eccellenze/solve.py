#!/usr/bin/env python3
from pwn import *

r = remote('albo.ctf.pascalctf.it', 7004)

# Weirdly sending arbitrary input leaks the flag
r.recvuntil(b'Enter your name: ')
r.sendline(b'Andrew')
r.recvuntil(b'Enter your surname: ')
r.sendline(b'Sigma')
r.recvuntil(b'Enter your date of birth (DD/MM/YYYY): ')
r.sendline(b'01/01/2000')
r.recvuntil(b'Enter your sex (M/F): ')
r.sendline(b'M')
r.recvuntil(b'Enter your place of birth: ')
r.sendline(b'Chongqing')

print(r.recvall().decode())
