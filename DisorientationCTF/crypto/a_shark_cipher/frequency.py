from collections import Counter

# Your emoji ciphertext
ciphertext = "🥻🦏🦌🥇🦏🦜🦔🦉🦓🦌🥇🦎🦈🦛🦌🦒🦌🦌🦗🦌🦙🦚🥇🦖🦍🥇🦛🦏🦌🥇🦚🦌🦈🦚🥓🥇🦚🦈🦍🦌🦎🦜🦈🦙🦋🦐🦕🦎🥇🦛🦏🦌🥇🦉🦙🦐🦋🦎🦌🦚🥇🦛🦖🥇🦛🦏🦌🥇🦋🦌🦗🦛🦏🦚🥇🦖🦍🥇🦛🦏🦌🥇🦜🦕🦒🦕🦖🦞🦕🥕🥇🦋🦐🦚🦖🦙🦐🦌🦕🦛🦈🦛🦐🦖🦕🦢🦚🦌🦈🦍🦓🦖🦖🦙🦆🦊🦈🦉🦓🦌🦚🦆🦉🦌🦞🦈🦙🦌🦤"

# Frequency of each emoji
freq = Counter(ciphertext)
total_length = len(ciphertext)
print("Emoji count +  relative frequencies (%):")
for emoji, count in freq.most_common():
    relative_freq = (count / total_length) * 100
    print(f"{emoji:<1} count: {count:>3}  frequency: {relative_freq:>6.2f}%")

# Actual letter frequencies from https://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
letter_frequency = [
    ("E", 12.02), ("T", 9.10), ("A", 8.12), ("O", 7.68), ("I", 7.31),
    ("N", 6.95), ("S", 6.28), ("R", 6.02), ("H", 5.92), ("D", 4.32),
    ("L", 3.98), ("U", 2.88), ("C", 2.71), ("M", 2.61), ("F", 2.30),
    ("Y", 2.11), ("W", 2.09), ("G", 2.03), ("P", 1.82), ("B", 1.49),
    ("V", 1.11), ("K", 0.69), ("X", 0.17), ("Q", 0.11), ("J", 0.10),
    ("Z", 0.09)
]
print("\nEnglish letter frequency reference (descending):")
for letter, freq in letter_frequency:
    print(f"{letter}: {freq:>3}%")

emoji_to_letter = {
    "🥻": "_",   # sari
    "🦏": "_",   # rhino
    "🦌": "E",   # deer
    "🥇": "T",   # medal
    "🦜": "_",   # parrot
    "🦔": "_",   # hedgehog
    "🦉": "_",   # owl
    "🦓": "_",   # zebra
    "🦎": "_",   # lizard
    "🦈": "_",   # shark
    "🦛": "_",   # hippo
    "🦒": "_",   # giraffe
    "🦗": "_",   # cricket
    "🦙": "_",   # llama
    "🦚": "_",   # peacock
    "🦖": "_",   # dino
    "🦍": "_",   # gorilla
    "🦋": "_",   # butterfly
    "🦐": "_",   # shrimp
    "🦕": "_",   # saur
    "🥓": "_",   # bacon
    "🥕": "_",   # carrot
    "🦢": "_",   # swan
    "🦊": "_",   # fox
    "🦤": "_",   # dodo
    "🦆": "_",   # duck
    "🦞": "_",   # lobster
}
translate_map = {ord(k): ord(v) for k, v in emoji_to_letter.items()}
decrypted = ciphertext.translate(translate_map)
print(decrypted)
