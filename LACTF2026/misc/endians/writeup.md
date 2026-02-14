# endians

From the given `gen.py` we know `chall.txt` contains our flag after being garbled with some unkown encoding.

---
Some context:

When text is written on a computer, the characters you see are stored as numbers (bytes) in 
memory. How we determine what number/bytes correspond to which character is dependent on the 
encoding system the text uses.

There are 3 main encodings we need to be concerned with:

**ASCII**
The ASCII encoding is pretty simple in which each character corresponds to exactly a single byte
as a representation. Because of this it can only represent 256 characters much too little to 
represent more complex text such as emojis or even **Japanese** text as the challenge describes.

**UTF-8**
UTF-8 is a more flexible encoding that can represent all Unicode characters. For ASCII characters (like English letters), UTF-8 uses the same single byte as ASCII. For other characters, it can use2-4 bytes. We can determine the length of each character via looking at the first four bits of thedata.

```
0xxxxxxx	1 byte (ASCII) 
110xxxxx	2 bytes       
1110xxxx	3 bytes      
11110xxx	4 bytes     
```

**UTF-16**
UTF-16 is an extended unicode encoding that uses 2 bytes (or more) for each character. It comes in two flavors:
- UTF-16 LE (Little Endian LSB -> MSB, eg. 0x0041 -> 41 00)
- UTF-16 BE (Big Endian  MSB -> LSB, eg. 0x0041 -> 00 41)

---

Now with this in mind let's analyse the text. To have some idea of how the text has been 
encoded let's look at the individual bytes: 
```
xxd chall.txt
00000000: e6b0 80e6 8480 e68c 80e7 9080 e698 80e7  ................
00000010: ac80 e384 80e5 bc80 e78c 80e7 9480 e788  ................
00000020: 80e3 8c80 e5bc 80e6 a080 e380 80e7 8080  ................
00000030: e694 80e5 bc80 e790 80e6 a080 e384 80e7  ................
00000040: 8c80 e5bc 80e6 9080 e380 80e6 9480 e78c  ................
00000050: 80e5 bc80 e6b8 80e3 8080 e790 80e5 bc80  ................
00000060: e69c 80e3 8c80 e790 80e5 bc80 e6b0 80e3  ................
00000070: 8080 e78c 80e7 9080 e5bc 80e3 8480 e6b8  ................
00000080: 80e5 bc80 e790 80e7 8880 e684 80e6 b880  ................
00000090: e78c 80e6 b080 e684 80e7 9080 e6a4 80e3  ................
000000a0: 8080 e6b8 80e2 8480 e7b4 80              ...........
```

We can tell this is encoded in UTF-8 by looking at the byte patterns. Notice that most bytes start with `0xe` (which is `0b1110xxxx`) , indicating 3-byte UTF-8 characters.

We can confirm this with:
```
file chall.txt
chall.txt: Unicode text, UTF-8 text, with no line terminators
```

So we know the garbled final result is stored as UTF-8.

---

Remember the generator does the following sequence:

```python
text = "lactf{REDACTED}"
endian = text.encode(encoding="???").decode(encoding="???")
with open("chall.txt", "wb") as file:
    file.write(endian.encode())
```

This performs:

- Encode the ASCII flag with encoding #1 → produces raw bytes
- Decode those bytes with encoding #2 → misinterprets the bytes, creating garbled Unicode text
- Encode the garbled text (defaults to UTF-8) → writes to file
Essentially, the original ASCII bytes are interpreted in the wrong encoding, which produces seemingly random Unicode characters. 

To recover the flag, we simply reverse the transformations performed by the generator.

We know the contents of chall.txt are stored as `UTF-8`, so the first step is to decode the file using UTF-8. This gives us the garbled Unicode string that was produced after the incorrect decoding step in the generator.

The garbling happened because the original ASCII bytes were interpreted as UTF-16 characters with the wrong endianness. As a result, pairs of ASCII bytes were treated as single UTF-16 code units, producing strange Unicode characters.

The solve script reverses this by swapping the byte order back to the original arrangement.
```
./solve.py
lactf{1_sur3_h0pe_th1s_d0es_n0t_g3t_l0st_1n_translati0n!}
```





