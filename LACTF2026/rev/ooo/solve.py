#!/usr/bin/env python3

# Copied from ooo.py
encrypted_flag = [
    205, 196, 215, 218, 225, 226, 1189, 2045, 2372,
    9300, 8304, 660, 8243, 16057, 16113, 16057,
    16004, 16007, 16006, 8561, 805, 346, 195,
    201, 154, 146, 223
]

# x_0 = ord('l')
x = [ord('l')]
for i in range(len(encrypted_flag)):
    # x[i+1] = y[i] - x[i]
    x.append(encrypted_flag[i] - x[i])

flag = ''.join(chr(c) for c in x)
print(flag)
