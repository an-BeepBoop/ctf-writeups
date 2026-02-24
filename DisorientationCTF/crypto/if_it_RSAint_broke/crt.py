"""Note from analysts:

This file was originally executed with configuration data stored
on the suspects computer. You might not be able to run it, as we
could not find this configuration data.
"""

from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
from Crypto.Util.Padding import pad, unpad
from distribution import send_to_jen, send_to_abe, send_to_mum
from getpass import getpass
import os

print("C.R.T.\n\nthe Covert Rendezvous Tool\n\n\n")

ps = [int(os.environ[k], 16) for k in ["P_A", "P_B", "P_C"]]
qs = [int(os.environ[k], 16) for k in ["Q_A", "Q_B", "Q_C"]]

Ns = [p*q for p,q in zip(ps, qs)]
e = 3
phis = [(p-1) * (q-1) for p,q in zip(ps, qs)]
ds = [pow(e, -1, phi) for phi in phis]

recipients = [send_to_jen, send_to_abe, send_to_mum]

def encrypt(plaintext: bytes, N: int) -> bytes:
    m = bytes_to_long(pad(plaintext, 256))
    c = pow(m, e, N)
    return long_to_bytes(c)

def decrypt(ciphertext: bytes, d: int, N: int) -> bytes:
    c = bytes_to_long(ciphertext)
    m = pow(c, d, N)
    return unpad(long_to_bytes(m), 256)

user_input = getpass("Location to encrypt: ")
plaintext = user_input.encode("utf-8")
print("---")
for recipient, d, N in zip(recipients, ds, Ns):
    print(f"\n\nPublic key: N=0x{N:x}\nPublic exponent: e=3")
    ciphertext = encrypt(plaintext, N)
    print(f"ciphertext = {ciphertext}")
    recipient(ciphertext)
