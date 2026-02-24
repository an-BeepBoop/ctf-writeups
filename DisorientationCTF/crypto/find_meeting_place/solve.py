#!/usr/bin/env python3


# ---------------  Helper functions copied from cipher.py -------------
multinv = [None, 1, 12, 8, 6, 14, 4, 10, 3, 18, 7, 21, 2, 16, 5, 20, 13, 19, 9, 17, 15, 11, 22]

def fromChar(ch):
    res = ord(ch) - ord('A')
    if res < 0 or res >= 23:
        print("Invalid character detected: \'" + ch + "\'")
        exit()
    return res

def fromNum(n):
    return chr(n + ord('A'))


plaintext = [
    "ENGINEERINGISBET",
    "TERTHANCOMPUTING"
]
ciphertext = [
    "AQBCQAASCQBCHKAT",
    "ITCQBTASTNVQWFER"
]
MOD = 23  

# Each character is encrypted using an affine cipher: y = (a * x + b) % MOD
# Solve for (a,b)
x1 = fromChar(plaintext[0][0])
y1 = fromChar(ciphertext[0][0])

x2 = fromChar(plaintext[0][2])
y2 = fromChar(ciphertext[0][2])

# y2 - y1 = a(x2 - x1) % MOD
# a = (x2 - x1)^-1 * (y2 -y1) % MOD
a = multinv[(x2 - x1) % MOD] * (y2 - y1) % MOD

# b = (y - a * x) % MOD
b = (y1 - a * x1) % MOD


# For s1 and s2 are starting index, shift ≡ s2 - s1 (mod 16)
# To find s1 and s2, we check where the first letter of each line appears in the ciphertext row.
c_first_line1 = (a * fromChar(plaintext[0][0]) + b) % MOD
c_first_line2 = (a * fromChar(plaintext[1][0]) + b) % MOD
index_line1 = ciphertext[0].index(fromNum(c_first_line1))
index_line2 = ciphertext[1].index(fromNum(c_first_line2))
shift = (index_line2 - index_line1) % 16

print("Full key: a =", a, ", b =", b, ", shift =", shift)
