#!/usr/bin/env python3
from collections import Counter

ciphertext = "🥻🦏🦌🥇🦏🦜🦔🦉🦓🦌🥇🦎🦈🦛🦌🦒🦌🦌🦗🦌🦙🦚🥇🦖🦍🥇🦛🦏🦌🥇🦚🦌🦈🦚🥓🥇🦚🦈🦍🦌🦎🦜🦈🦙🦋🦐🦕🦎🥇🦛🦏🦌🥇🦉🦙🦐🦋🦎🦌🦚🥇🦛🦖🥇🦛🦏🦌🥇🦋🦌🦗🦛🦏🦚🥇🦖🦍🥇🦛🦏🦌🥇🦜🦕🦒🦕🦖🦞🦕🥕🥇🦋🦐🦚🦖🦙🦐🦌🦕🦛🦈🦛🦐🦖🦕🦢🦚🦌🦈🦍🦓🦖🦖🦙🦆🦊🦈🦉🦓🦌🦚🦆🦉🦌🦞🦈🦙🦌🦤"

freq = Counter(ciphertext)
total_length = len(ciphertext)
print("Emoji count +  relative frequencies (%):")
for emoji, count in freq.most_common():
    relative_freq = (count / total_length) * 100
    print(f"{emoji:<1} count: {count:>3}  frequency: {relative_freq:>6.2f}%")

# Statistical letter frequencies alphanumeric upper/lower case and punctuation relative to the following source
# https://www.researchgate.net/publication/8090755_Case-sensitive_letter_and_bigram_frequency_counts_from_large-scale_English_corpora
letter_frequency = [
    # Space + lowercase
    (" ", 17.166), ("e", 10.266), ("t", 7.516), ("a", 6.532), ("o", 6.159),
    ("n", 5.713),  ("i", 5.668),  ("s", 5.317), ("r", 4.988), ("h", 4.979),
    ("l", 3.318),  ("d", 3.283),  ("u", 2.276), ("c", 2.234), ("m", 2.026),
    ("f", 1.983),  ("w", 1.704),  ("g", 1.625), ("p", 1.504), ("y", 1.428),
    ("b", 1.259),  ("v", 0.796),  ("k", 0.561), ("x", 0.141), ("j", 0.097),
    ("q", 0.084),  ("z", 0.051),

    # Uppercase
    ("E", 0.389), ("T", 0.291), ("A", 0.280), ("I", 0.265), ("S", 0.253),
    ("O", 0.234), ("H", 0.233), ("W", 0.222), ("B", 0.173), ("C", 0.166),
    ("M", 0.161), ("D", 0.136), ("F", 0.106), ("R", 0.105), ("G", 0.093),
    ("L", 0.088), ("N", 0.085), ("P", 0.079), ("J", 0.077), ("K", 0.068),
    ("U", 0.062), ("Y", 0.060), ("V", 0.031), ("Q", 0.008), ("X", 0.004),
    ("Z", 0.002),

    # Punctuation + braces
    (".", 0.650), (",", 0.614), ("'", 0.243), ('"', 0.226), ("-", 0.153),
    ("?", 0.056), (":", 0.034), (";", 0.032), ("(", 0.022), (")", 0.022),
    ("!", 0.009), ("{", 0.005), ("}", 0.005),

    # Numbers
    ("0", 0.100), ("1", 0.100), ("2", 0.100), ("3", 0.100), ("4", 0.100),
    ("5", 0.100), ("6", 0.100), ("7", 0.100), ("8", 0.100), ("9", 0.100),
]
print("\nEnglish letter frequency reference (descending):")
for letter, freq in letter_frequency:
    print(f"{letter}: {freq:>3}%")

emoji_to_letter = {
    "🥻": "_",   
    "🦏": "h",  
    "🦌": "e", 
    "🥇": " ",   
    "🦜": "u",   
    "🦔": "_",   
    "🦉": "b",   
    "🦓": "_",   
    "🦎": "g",   
    "🦈": "a",   
    "🦛": "t",   
    "🦒": "_",   
    "🦗": "_",   
    "🦙": "r",   
    "🦚": "s",   
    "🦖": "o",   
    "🦍": "f",   
    "🦋": "d",   
    "🦐": "i",   
    "🦕": "n",   
    "🥓": "_",   
    "🥕": "_",   
    "🦢": "_",   
    "🦊": "_",   
    "🦤": "_",   
    "🦆": "_",   
    "🦞": "_",  
}
translate_map = {ord(k): ord(v) for k, v in emoji_to_letter.items()}
decrypted = ciphertext.translate(translate_map)
print(decrypted)
