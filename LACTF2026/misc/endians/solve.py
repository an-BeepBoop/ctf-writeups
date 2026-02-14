#!/usr/bin/env python3
with open("chall.txt", "rb") as f:
    data = f.read()

flag = data.decode(encoding="utf-8").encode(encoding="UTF-16BE").decode(encoding="UTF-16LE")
print(flag)
