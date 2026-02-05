from pwn import *
import re
import numpy as np

io = remote('cramer.ctf.pascalctf.it', 5002)
data = io.recvall(timeout=2).decode()

# Matches any string of the form k*x_n where k,n are integers
lhs_re = re.compile(r'([+-]?\d+)\*x_(\d+)')

# Get all the equation lines as strings
lines = [l for l in data.splitlines() if '=' in l]

# Convert to np array and solve Ax = b
n = len(lines)
A = [[0]*n for _ in range(n)]
b = []
for row, line in enumerate(lines):
    left, right = line.split('=')
    b.append(int(right.strip()))

    for coef, idx in lhs_re.findall(left):
        A[row][int(idx)] = int(coef)
A = np.array(A, dtype=float)
b = np.array(b, dtype=float)
x = np.linalg.solve(A, b)
x = np.rint(x).astype(int)

flag = ''.join(chr(v) for v in x)
print(flag)
