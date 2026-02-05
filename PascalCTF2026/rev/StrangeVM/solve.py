#!/usr/bin/env python3

flag_bytes = bytes.fromhex('564c755c386d39586c283e577b5f3f54445b7120821b8b5080467e158a577d5a505481518c0c9444')

flag = []
for i in range(40):
    if i % 2 == 0:
        flag.append((flag_bytes[i] - i) & 0xFF)  
    else:
        flag.append((flag_bytes[i] + i) & 0xFF) 

print(bytes(flag))  # b'VMs_4r3_d14bol1c4l_3n0ugh_d0nt_y0u_th1nk'

with open('test.bin', 'wb') as f:
    f.write(bytes(flag))
