#!/usr/bin/env python3
import re
import instruction

MEMORY_PATTERN = re.compile(
    r'\[0x([0-9A-Fa-f]+)\]\s*=\s*0x([0-9A-Fa-f]+)'
)

def parse_file(filename: str) -> Dict[int, int]:
    memory = {}
    with open(filename) as f:
        for line in f:
            m = MEMORY_PATTERN.match(line.strip())
            if not m:
                continue
            memory[int(m.group(1), 16)] = int(m.group(2), 16)
    return memory

def disassemble_word(word: int) -> str:
    instr = instruction.Instruction.from_word(word)
    if instr is None:
        return f".word 0x{word:04X}   ; unknown opcode 0x{(word >> 12) & 0xF:X}"
    return str(instr)


if __name__ == "__main__":
    memory = parse_file("mystery.txt")
    with open("mystery.quac", "w") as f:
        for addr in sorted(memory.keys()):
            word = memory[addr]
            asm = disassemble_word(word)
            f.write(f"{asm}\n")
