#!/usr/bin/env python3

# Top-left to bottom-right
hex_colors = [
    "#646973", "#6f7269", "#656e74",
    "#617469", "#6f6e7b", "#62e56a",
    "#76316c", "#4c6131", "#6e597d"
]

rgb_values = []
for hex_color in hex_colors:
    hex_color = hex_color.lstrip("#")  
    r = int(hex_color[0:2], 16)
    g = int(hex_color[2:4], 16)
    b = int(hex_color[4:6], 16)
    rgb_values.extend([r, g, b])  

flag = ''.join(chr(v) for v in rgb_values)
print(flag)
