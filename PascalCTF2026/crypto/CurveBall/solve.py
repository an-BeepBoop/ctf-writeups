from pwn import *

# Copied from penguin.py
words = [
    "biocompatibility", "biodegradability", "characterization", "contraindication",
    "counterbalancing", "counterintuitive", "decentralization", "disproportionate",
    "electrochemistry", "electromagnetism", "environmentalist", "internationality",
    "internationalism", "institutionalize", "microlithography", "microphotography",
    "misappropriation", "mischaracterized", "miscommunication", "misunderstanding",
    "photolithography", "phonocardiograph", "psychophysiology", "rationalizations",
    "representational", "responsibilities", "transcontinental", "unconstitutional"
]

# Build the lookup
ciphertext_lookup = {}
io = remote('penguin.ctf.pascalctf.it', 5003)
word_idx = 0 
for round in range(7):
    # Wait for prompt
    io.recvuntil(b"Give me 4 words to encrypt")

    batch = words[word_idx:word_idx+4]
    word_idx += 4

    # Send 4 words
    for w in batch:
        io.sendline(w.encode())

    # Retrieve encrypted words
    io.recvuntil(b"Encrypted words:")
    line = io.recvline().decode().strip()
    encrypted = line.split()

    # Build reverse lookup (ciphertext, word)
    for c, w in zip(encrypted, batch):
        ciphertext_lookup[c] = w


# Now guess the words based on the lookup
io.recvuntil(b"Ciphertext:")
line = io.recvline().decode().strip()
ciphertext = line.split()
for i in range(5):
    if (ciphertext[i] in ciphertext_lookup):
        word = ciphertext_lookup[ciphertext[i]]
        io.sendline(word.encode())

# Should print the flag now
io.interactive()
