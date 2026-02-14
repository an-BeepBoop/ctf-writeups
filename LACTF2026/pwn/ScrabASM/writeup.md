# ScrabASM

The given program as the name suggests simulates a game of 'scrabble' in which the player is 
initially given a hand of $14$ tiles / bytes to control. At each turn the player is allowed to 
`swap()` their tile positions from index $0-13$. Eventually the player is allowed to choose to 
`play()` their hand.

Playing results in the program requesting a page from the operating system at 
`#define BOARD_ADDR 0x13370000UL` which notably has read, write and importantly 
**execute** permissions and copies their hand to the board.

Afterwards it will copy their hand to the board and runs the following: 
`((void (*)(void))board)();` This essentially treats the board as a function / executable piece of code that the user controls which is a clear **remote code execution** vulnerability.

That said, the limited hand size of $14$ bytes makes it impractical to directly leak the flag by 
spawning a shell instance via something like `exec("/bin/sh")` or something similar. So, as a 
workaround we can craft a `read()` syscall that allows the user to get further input from `STDIN` 
to extend this limitation.

```c
# READ n bytes from STDIN and store it at BOARD_ADDR + HAND_SIZE
# This is because after we read, this will be the IP/PC will be looking at.
read(0, BOARD_ADDR + HAND_SIZE, n)
```

Note that our ASM must be able to be crafted from our initial hand (via swapping) so it must be 
confined to $14$ bytes. This is an important limitation so we have to the parameters of the syscall have to be carefully chosen.

An additional complication arises from the fact that the board tiles are **randomly generated** using `rand()`, with the seed initialized via the current time `srand(time(NULL))`. Each call to `swap()` replaces the hand index with a further generated `rand() & 0xff` output. As a result, once the tiles are swapped we do not know their exact values as there is no way to read the hand after the initial hand is displayed. However, because `rand()` is a deterministic PRNG and the seed (the current time) is known, its output can be predicted. This allows us to advance the PRNG in a controlled manner: by repeatedly swapping a specific tile, we can deterministically cycle through future `rand()` outputs until the desired byte appears at that position.


With these the attack strategy is clear:
1. Retrieve the `srand()`  seed 
2. Craft the `read()` syscall with the future `rand()` outputs now known
3. Craft and insert asm to spawn the shell instance
4. Now we have shell access `cat flag.txt`
See `solve.py` for details.


```
./solve.py REMOTE
lactf{gg_y0u_sp3ll3d_sh3llc0d3}
```




