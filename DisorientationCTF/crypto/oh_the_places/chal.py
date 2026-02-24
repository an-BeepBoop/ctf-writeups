import os

KEY_LENGTH = 16
FLAG = os.environ["FLAG"].encode("utf-8")

KEY = os.environ["KEY"].encode("utf-8")
assert len(KEY) == KEY_LENGTH

def encrypt(plaintext: bytes) -> bytes:
    key_repeated = KEY * (len(plaintext) // KEY_LENGTH + 1)
    return bytes(b^k for b,k in zip(plaintext, key_repeated))

print("""Oh The Places™ (OTP) is an unbreakable encryption service for all your privacy needs!
Use this service to encrypt any secret message securely...\n\n""")
print(f"FLAG: {encrypt(FLAG)}\n")
while True:
    plaintext = input("Enter a string to encrypt: ").encode("utf-8", errors="surrogatepass")
    print(f"{plaintext} ==> {encrypt(plaintext)}\n")
