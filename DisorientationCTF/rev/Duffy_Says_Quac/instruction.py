#!/usr/bin/env python3

from enum import IntEnum
from dataclasses import dataclass


# QuAC-ISAv3
# https://comp.anu.edu.au/courses/comp2300/resources/08-QuAC-ISA/#instruction-encoding

class Opcode(IntEnum):
    MOVL = 0b0000
    SETH = 0b0010
    LDR  = 0b0100
    STR  = 0b0111
    AND  = 0b1000
    ORR  = 0b1001
    ADD  = 0b1010
    SUB  = 0b1011

class Reg(IntEnum):
    rz = 0b000   # zero register, always reads 0
    r1 = 0b001
    r2 = 0b010
    r3 = 0b011
    r4 = 0b100
    # 0b101 undefined
    fl = 0b110   # flag register
    pc = 0b111   # program counter

class Flags(IntEnum):
    Z = 0   # bit 0 - zero
    N = 1   # bit 1 - negative
    V = 2   # bit 2 - overflow
    C = 3   # bit 3 - carry

@dataclass
class Instruction:
    opcode: Opcode
    cond: bool       # bit 11
    rd: Reg
    ra: Reg | None = None
    rb: Reg | None = None
    imm8: int | None = None

    @classmethod
    def from_word(cls, word: int) -> "Instruction | None":
        opcode_val = (word >> 12) & 0xF
        cond       = bool((word >> 11) & 0x1)
        rd         = (word >>  8) & 0x7
        ra         = (word >>  4) & 0x7
        rb         =  word        & 0x7
        imm8       =  word        & 0xFF

        try:
            opcode = Opcode(opcode_val)
            rd_reg = Reg(rd)
        except ValueError:
            return None

        if opcode in (Opcode.MOVL, Opcode.SETH):
            return cls(opcode, cond, rd=rd_reg, imm8=imm8)
        if opcode in (Opcode.LDR, Opcode.STR):
            try:
                ra_reg = Reg(ra)
            except ValueError:
                return None
            return cls(opcode, cond, rd=rd_reg, ra=ra_reg)
        if opcode in (Opcode.AND, Opcode.ORR, Opcode.ADD, Opcode.SUB):
            try:
                ra_reg = Reg(ra)
                rb_reg = Reg(rb)
            except ValueError:
                return None
            return cls(opcode, cond, rd=rd_reg, ra=ra_reg, rb=rb_reg)
        return None

    def __str__(self) -> str:
        c = "z" if self.cond else ""
        match self.opcode:
            case Opcode.MOVL: return f"movl{c} {self.rd.name}, 0x{self.imm8:02X}"
            case Opcode.SETH: return f"seth{c} {self.rd.name}, 0x{self.imm8:02X}"
            case Opcode.LDR:  return f"ldr{c}  {self.rd.name}, [{self.ra.name}]"
            case Opcode.STR:  return f"str{c}  {self.rd.name}, [{self.ra.name}]"
            case Opcode.AND:  return f"and{c}  {self.rd.name}, {self.ra.name}, {self.rb.name}"
            case Opcode.ORR:  return f"orr{c}  {self.rd.name}, {self.ra.name}, {self.rb.name}"
            case Opcode.ADD:  return f"add{c}  {self.rd.name}, {self.ra.name}, {self.rb.name}"
            case Opcode.SUB:  return f"sub{c}  {self.rd.name}, {self.ra.name}, {self.rb.name}"
