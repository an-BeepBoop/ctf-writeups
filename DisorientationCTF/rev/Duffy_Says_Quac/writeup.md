# Duffy Says Quac

The challenge description hints that the problem relates to Duffy’s favourite assembly language (version 3), namely [QuAC-ISA v3](https://comp.anu.edu.au/courses/comp2300/resources/08-QuAC-ISA/#instruction-encoding).

We are given a file `mystery.txt`, which represents the raw contents of memory for a QuAC machine. In other words, this file is the program itself, encoded as machine words.

We also have the input which gives us the initial constraint:

```
mem[0x00F0] = 0xFADE
```

---

## Approach

To solve the challenge, we:

1. **Convert `mystery.txt` into QuAC instructions**
   Using `quac_assembler.py` and `instruction.py`, we decode the raw memory contents into valid QuAC-ISA v3 instructions.
2. **Simulate execution with the constrained input**
   We execute the program with the initial state:

There are two main ways to simulate execution:

### Option 1: Use a QuAC CPU in Digital

If you were a student that took COMP2300 in 2025, you will have a QuAC-ISAv3 compatible CPU implemented in [Digital](https://github.com/hneemann/Digital/). We can load the program into the CPU and run it.

### Option 2: Use a Virtual Machine

If a hardware simulation is unavailable, we can instead emulate execution using a simple VM.
The provided `vm.py` and `solve.py` simulate the QuAC instruction set and execute the program directly.

Simulating the program yields:
```bash
./solve.py 
  PC=0x0000  movl r1, 0xF0
  PC=0x0002  ldr  r1, [r1]
  PC=0x0004  movl r2, 0x10
  PC=0x0006  add  r1, r1, r2
  PC=0x0008  movl r2, 0x01
  PC=0x000A  sub  r1, r1, r2
  PC=0x000C  movl r3, 0xFF
  PC=0x000E  seth r3, 0x03
  PC=0x0010  movl r4, 0x01
  PC=0x0012  add  r3, r3, r4
  PC=0x0014  orr  r1, r1, r3
  PC=0x0016  movl r2, 0xF0
  PC=0x0018  str  r1, [r2]
[vm] halt: no instruction at PC=0x001A

--- registers ---
  r1   = 0xFEED  [RW]
  r2   = 0x00F0  [RW]
  r3   = 0x0400  [RW]
  r4   = 0x0001  [RW]
  fl   = 0x0002  (N)  [W]
  pc   = 0x001A  [W]

--- accessed memory ---
  [0x00F0] = 0xFEED  [RW]
```
Thus the final flag is **disorientation{0xFEED}**.
