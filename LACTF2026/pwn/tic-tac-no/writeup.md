# tic-tac-toe
Note that tic-tac-toe is a 'solved' game. So under normal circumstances it is **IMPOSSIBLE**
to win if the other player is playing OPTIMALLY. We must therefore exploit the board somehow.

The vulnerability is the following line in `playerMove()`

The user is allowed to write their player character of 'X' to a given board
index of `char board[9]`. However, the logic allows the user to perform
an out of bounds write when the index is invalid.

```c
if(index >= 0 && index < 9 && board[index] != ' '){
 printf("Invalid move.\n");
```

Invalid moves are only detected when **ALL 3 conditions are met**. So an invalid index
where the memory address of `board[index] != ' '` is a valid move.

Note that the `winner` variable only exists on the stack frame of the `main` function so writing to it is a bit more difficult. Instead we can trick the computer into thinking it also is the `player` character so when the `checkWin()` function triggers we leak the flag.

From gdb, we know the compiler arranged the global variables to be BEFORE the board.
```
(gdb) p &board
$1 = (<data variable, no debug info> *) 0x4068 <board>
(gdb) p &player
$2 = (<data variable, no debug info> *) 0x4050 <player>
(gdb) p &computer
$3 = (<data variable, no debug info> *) 0x4051 <computer>
```

$$
0x4068 - 0x4051 = 0x17 = 23 bytes
$$


So we need to write `board[-23] = 'X';`
The index is calculated as  $(x - 1) * 3 + (y - 1)$
Using $x = -7$ and $y = 2$ satisfies this $(-7 - 1) * 3 + (2 - 1) = -24 + 1 = -23$

Thus we have the following solve
```
./solve.py REMOTE
How's this possible? Well, I guess I'll have to give you the flag now.
lactf{th3_0nly_w1nn1ng_m0ve_1s_t0_p1ay}
```





