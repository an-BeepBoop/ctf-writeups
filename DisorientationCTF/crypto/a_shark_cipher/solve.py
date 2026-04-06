#!/usr/bin/env python3

# Frequency analysis shows MEDAL maps to SPACE"
MEDAL = ord("🥇")  
SPACE = ord(" ")  

ciphertext = "🥻🦏🦌🥇🦏🦜🦔🦉🦓🦌🥇🦎🦈🦛🦌🦒🦌🦌🦗🦌🦙🦚🥇🦖🦍🥇🦛🦏🦌🥇🦚🦌🦈🦚🥓🥇🦚🦈🦍🦌🦎🦜🦈🦙🦋🦐🦕🦎🥇🦛🦏🦌🥇🦉🦙🦐🦋🦎🦌🦚🥇🦛🦖🥇🦛🦏🦌🥇🦋🦌🦗🦛🦏🦚🥇🦖🦍🥇🦛🦏🦌🥇🦜🦕🦒🦕🦖🦞🦕🥕🥇🦋🦐🦚🦖🦙🦐🦌🦕🦛🦈🦛🦐🦖🦕🦢🦚🦌🦈🦍🦓🦖🦖🦙🦆🦊🦈🦉🦓🦌🦚🦆🦉🦌🦞🦈🦙🦌🦤"


plaintext = ''.join(chr(ord(x) - (MEDAL - SPACE)) for x in ciphertext)
print(plaintext)



