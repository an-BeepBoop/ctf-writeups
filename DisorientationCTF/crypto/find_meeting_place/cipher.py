import sys

## Parse arguments

usage = "Usage: python3 cipher.py <-e or -d> <input file> <output file> <a> <b> <s>"

argv = sys.argv 
if len(argv) < 7:
    print(usage)
    exit()

mode = argv[1]
if mode != '-e' and mode != '-d':
    print(usage)
    exit()

shouldEncrypt = mode == '-e'

infile = argv[2]
outfile = argv[3]

#Our key (a, b, shift)
a = int(argv[4])
b = int(argv[5])
shift = int(argv[6])

# Multiplicative inverses of mod 23. i.e. (x * multinv[x]) % 23 is 1 for all x in the range 0 to 22.
multinv = [None, 1, 12, 8, 6, 14, 4, 10, 3, 18, 7, 21, 2, 16, 5, 20, 13, 19, 9, 17, 15, 11, 22]

## Initialise input

def fromChar(ch):
    res = ord(ch) - ord('A')
    if res < 0 or res >= 23:
        print("Invalid character detected: \'" + ch + "\'")
        exit()
    return res

def fromNum(n):
    return chr(n + ord('A'))

def encrypt(state, a, b, shift):
    res = []
    s = 0
    for line in state:
        curr = [None] * 16
        i = s 
        for ch in line:
            n = (a * fromChar(ch) + b) % 23
            curr[i] = fromNum(n)
            i = (i + 1) % 16
        res.append(curr)
        s = (s + shift) % 16
    return res

def decrypt(state, a, b, shift):
    res = []
    s = 0
    for line in state:
        curr = [None] * 16
        i = s
        for ch in line:
            n = ((fromChar(ch) - b) * multinv[a]) % 23
            curr[i] = fromNum(n)
            i = (i+1)%16
        res.append(curr)
        s = (s-shift) % 16
    return res

def serialise(state):
    string = ""
    for i in range(len(state)):
        line = state[i]
        for j in range(len(line)):
            ch = line[j]
            string = string + ch
            if(j != len(line)-1):
                string = string + ' '
        if(i != len(state)-1):
            string = string + '\n'
    return string

with open(infile, 'r') as file:
    plaintext = file.read()

split = plaintext.split("\n")
arr = []
for line in split:
    splitLine = line.split(" ")
    # Added this extra line 
    if not line:
        continue
    if(len(splitLine) != 16):
        print("Each line in the input file must contain exactly 16 characters.")
        exit()
    arr.append(splitLine)


file.close()

if shouldEncrypt:
    res = encrypt(arr, a, b, shift)
else:
    res = decrypt(arr, a, b, shift)

with open(outfile, 'w+') as file:
    file.write(serialise(res))
file.close()
