# Average Heap Challenge 

The given `average` binary implements a simple player management system backed by heap allocations.
The user can:
- `create_player()` - Allocates a chunk and stores name + message
- `delete_player()` - Frees the player's chunk
- `print_players()` - Displays all players' names and messages
- `check_target()`  - Checks if a target value equals `0xDEADBEEFCAFEBABE`
- `exit()` - Terminates the program

Most notably, the program internally maintains a special heap variable called `target` which is 
initialised to `0xBABEBABEBABEBABE`. Our fourth option the `check_target()` leaks the flag if the `target` variable is `0xDEADBEEFCAFEBABE` which makes our point of attack clear. 

---
Some context:

Heap allocations use the standard library `malloc()` call. As such each allocation is internally 
represented by a **chunk** containing metadata followed by user controlled data. 

According to https://github.com/lattera/glibc/blob/master/malloc/malloc.c
+------------------------+
| prev_size (8 bytes)    | <- Only used if prev_chunk is free
+------------------------+
| size (8 bytes)         | <- Low bits include flags
|                        |     eg. PREV_INUSE
+------------------------+
| user-controlled data   | <- pointer returned by malloc()
|        ...             |
+------------------------+
The allocator intrinsically trusts chunk metadata such as the `size` and `prev_size` fields when 
performing these allocation/free. If this metadata is corrupted, the allocator can be tricked 
into misclassifying a chunk’s size or boundaries, causing adjacent memory to be treated as part of the same allocation.

For allocation, glibc does not manage freed chunks in a single global list. Instead, it maintains 
**multiple free lists / bins** that group chunks by size and allocation state. When a chunk is 
freed, it is placed into a size‑specific bin, and future allocations of the same size may be 
satisfied directly from that bin, which significantly speeds up allocation time.

In the general allocator (fastbins, small bins, large bins), freed chunks may be **coalesced** 
with adjacent free chunks. This coalescing merges neighboring free chunks into a single larger 
chunk.

Note that this `malloc()` implementation uses concurrency (threads) to speed up 
allocations. Instead of relying solely on global bins protected by locks, glibc uses a 
per‑thread cache known as a **tcache**. Tcache is designed for speed and simplicity: freed 
chunks are cached locally to the local thread and reused directly without interacting with 
the global allocator.

A crucial difference is that **tcache does not perform coalescing**. When a chunk is freed into 
tcache, it is stored as‑is, without checking or merging with adjacent free chunks. As a result, 
the allocator continues to treat neighboring chunks as separate allocations, even if their 
metadata suggests they could be combined. 

Note that any glibc version past 2.26 uses tcache. The version used here is 2.39. Check with
```
strings libc.so.6 | grep GLIBC_
```

Crucially, the tcache bin a chunk is placed into is determined by the chunk’s size field 
**at the moment it is freed**. If this metadata has been corrupted beforehand, the allocator 
will trust the modified value and insert the chunk into an incorrect bin. Because no coalescing 
or boundary verification occurs, this corrupted chunk can later be reallocated as a larger object 
than it physically is in memory, causing its writable region to **overlap adjacent heap allocations**.

---

The actual vulnerability is a heap overflow in `create_player()` in which the helper functions
`read_name()` and `read_message()` allow writing up to 78 bytes of data into a player chunk which is fixed to be 72 bytes.

Note that this original overflow is **not** enough to directly modify the `target` value as it 
is at an offset of 80 from the player4's chunk whereas the overflow only reaches 78. However, 
we can modify the adjacent chunk's `size` field of its metadata. 'Tricking' the allocator into 
treating adjacent memory as part of the same chunk.

In this challenge, the player chunk initially has a size of `0x50` (size field `0x51`) and 
therefore resides in the `0x50` tcache bin. Even after its size field is overwritten to `0x71`, 
the chunk remains in the `0x50` bin until it is reallocated and freed again. To migrate the chunk 
into the correct bin, the exploit first reallocates it as a `0x50` chunk, frees it, and only then 
requests a `0x70` allocation.

This allocation order is important for the exploit. Because only **after** the chunk is placed 
into the `0x70` tcache bin does glibc return it as a larger allocation whose usable region 
overlaps the `target` chunk, allowing the `target` value to be overwritten.

Before
[ Player 4 Chunk ]
| prev_size | size=0x51 |<----------- 72 bytes user data ---------->|

After
[ Player 4 Chunk ]
| prev_size | size=0x71 |<---------------- expanded user data ----------------->|

                                        |
                                        | allocator believes Player 4 owns this
                                        v
[ Target Chunk ]
| prev_size=0x50 | size=0x21 | target = 0xBABEBABEBABEBABE |
                         ^
                         |
              now inside writable region

With the `target` now within the writable region of player4's chunk. We can simply edit player4's 
user data to the expected value to trigger the flag. 

---

Note that importantly when the program is initialised, `setup_chall()` allocates and 
frees 4 players than allocates the `target`. So initially the heap will look like the following.

 [ Player 0 ] → [ Player 1 ] → [ Player 2 ] → [ Player 3 ]  → [ Target ]
   0x50         0x50         0x50         0x50          0x20

No **coalescing!**
[ free 0 ] → [ free 1 ] → [ free 2 ] → [ free 3 ]  → [ Target ]
                                                0x20

---

Thus the final exploit is as follows:

First, multiple players are created to populate the heap with player-sized allocations. This is 
because `setup_chall()` initially allocates and frees all player chunks during setup, these allocations are served from tcache, resulting in a predictable heap layout where player chunks are 
adjacent to the target chunk allowing a later corruption to manipulate the `target` value.

Next, a player is created with a carefully crafted name length and message length that trigger the heap overflow in `create_player()`. This overflow does not reach the target value directly, but it overwrites the `size` field of the adjacent player chunk’s metadata, changing it from `0x51` to 
`0x71`. At this point, the allocator has not yet acted on the corrupted metadata; the chunk still 
resides in the `0x50` tcache bin.

The corrupted chunk is then reallocated as a normal `0x50` chunk and freed again. 
This step is critical because tcache bin placement is decided at free time. Since the 
chunk’s size field now reports `0x71`, freeing it causes glibc to insert it into the `0x70` 
tcache bin instead of the original `0x50` bin. This effectively migrates the chunk between 
bins based on the corrupted metadata.

After this migration, a new allocation request of size `0x70` is made. glibc satisfies this 
request by returning the same corrupted chunk from the `0x70 tcache bin. Because the allocator 
now believes the chunk is larger than it actually is, its usable region **overlaps** with the 
adjacent `target` chunk.

Finally, user input written into the reallocated player chunk overwrites the target value with 
`0xDEADBEEFCAFEBABE`. Invoking `check_target()` confirms the overwrite and causes the program to 
leak the flag.

```python
#!/usr/bin/env python3
from pwn import *

if args.REMOTE:
    # run with: python3 solve.py REMOTE
    r = remote("ahc.ctf.pascalctf.it", 9003 )
else:
    r = process("./average")

for i in range(5):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b': ', str(i).encode())
    r.sendlineafter(b'? ', b'0')
    
    r.sendlineafter(b'name: ', b'abcd' if i != 3 else b'a'*39)
    r.sendlineafter(b'message: ', b'efgh' if i != 3 else b'b'*32 + b'\x71')

r.sendlineafter(b'> ', b'2')
r.sendlineafter(b': ', b'4')

r.sendlineafter(b'> ', b'1')
r.sendlineafter(b': ', b'4')
r.sendlineafter(b'? ', b'32')
r.sendlineafter(b'name: ', b'abcd')
r.sendlineafter(b'message: ', p64(0xdeadbeefcafebabe)*4)
r.sendlineafter(b'> ', b'5')
r.interactive()

