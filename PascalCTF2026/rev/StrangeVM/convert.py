#!/usr/bin/env python3
import struct

# Mapping of opcodes to instruction names
OPCODES = {
    0: "HALT",
    1: "ADD",
    2: "SUB",
    3: "MOD",
    4: "STORE",
    5: "INPUT",  
    6: "JZ"
}

with open("code.pascal", "rb") as f:
    bytecode = f.read()

pc = 0  
while pc < len(bytecode):
    opcode = bytecode[pc]
    instr_name = OPCODES.get(opcode, f"UNKNOWN({opcode})")

    # HALT instruction is only 1 byte
    if opcode == 0:
        print(f"{pc:04}: {instr_name}")
        pc += 1
        continue

    # Extract 4-byte address (little-endian)
    addr_bytes = bytecode[pc + 1: pc + 5]
    address = struct.unpack("<I", addr_bytes)[0]

    # INPUT instruction is 5 bytes (doesn't have a value byte)
    if opcode == 5:
        print(f"{pc:04}: {instr_name} mem[{address}]")
        pc += 5  
        continue

    # Extract 1-byte value for other instructions
    value = bytecode[pc + 5]

    # JZ instruction prints offset instead of value
    if opcode == 6:
        print(f"{pc:04}: {instr_name} mem[{address}] offset {value}")
    else:
        print(f"{pc:04}: {instr_name} mem[{address}] {value}")

    # Move program counter to next instruction
    pc += 6
