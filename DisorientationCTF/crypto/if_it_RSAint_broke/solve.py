#!/usr/bin/env python3
import re
from ast import literal_eval
from sympy.ntheory.modular import crt
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad


# From log.txt we know the SAME message 'm' is sent to 3 different
# people but encrypted under different conditions. In the src code
# the modular exponent used is 3. 

# This satisfies the conditions for a Håstad's broadcast attack detailed below
# https://en.wikipedia.org/wiki/Coppersmith's_attack#H.C3.A5stad.27s_broadcast_attack

# Parse parameters from log.txt
with open("log.txt", "r", encoding="utf-8", errors="ignore") as f:
    log = f.read()

Ns = [int(n, 16) for n in re.findall(r"N=0x([0-9a-fA-F]+)", log)]

pattern = r"ciphertext = (b'(?:\\.|[^'])*')"
ciphertexts = [literal_eval(m.group(1)) for m in re.finditer(pattern, log, re.DOTALL)]
cs = [int.from_bytes(c, "big") for c in ciphertexts]

# Use CRT to solve for m^3
m_cubed, _ = crt(Ns, cs)
m, exact = iroot(int(m_cubed), 3)
if not exact:
    print("Warning: cube root not exact, result may be slightly off")

# Convert to bytes and remove padding
plaintext_padded = long_to_bytes(int(m))
plaintext = unpad(plaintext_padded, 256)
print("Recovered message:", plaintext.decode())
