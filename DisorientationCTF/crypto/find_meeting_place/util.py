'''
This is just a copy of cipher.py with only the helper functions for reuse in the solve script.
'''



# Multiplicative inverses of mod 23. i.e. (x * multinv[x]) % 23 is 1 for all x in the range 0 to 22.
multinv = [None, 1, 12, 8, 6, 14, 4, 10, 3, 18, 7, 21, 2, 16, 5, 20, 13, 19, 9, 17, 15, 11, 22]


def fromChar(ch):
    res = ord(ch) - ord('A')
    if res < 0 or res >= 23:
        print("Invalid character detected: \'" + ch + "\'")
        exit()
    return res

def fromNum(n):
    return chr(n + ord('A'))

