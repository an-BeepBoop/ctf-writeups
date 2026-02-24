#!/usr/bin/env python3

from instruction import Instruction, Opcode, Reg, Flags

def access_tags(key, read_set: set, write_set: set) -> str:
    """
    Utility helper used for debugging output.

    Returns:
        "[R]"  if the key was read
        "[W]"  if the key was written
        "[RW]" if both
        ""     if neither
    """
    tags = ("R" if key in read_set else "") + ("W" if key in write_set else "")
    return f"[{tags}]" if tags else ""

def alu(instr: Instruction, a: int, b: int) -> tuple[int, bool, bool]:
    """
    Software implementation of the ALU datapath.

    Returns:
        (result, carry_flag, overflow_flag)

    All arithmetic is 16-bit (QuAC is a 16-bit architecture).
    """
    match instr.opcode:
        case Opcode.AND:
            return a & b, False, False
        case Opcode.ORR:
            return a | b, False, False
        case Opcode.ADD:
            full     = a + b
            result   = full & 0xFFFF
            carry    = full > 0xFFFF
            overflow = ((not (a & 0x8000) and not (b & 0x8000) and bool(result & 0x8000)) or
                            ((a & 0x8000) and     (b & 0x8000) and not (result & 0x8000)))
            return result, carry, overflow
        case Opcode.SUB:
            full     = a - b
            result   = full & 0xFFFF
            carry    = full < 0
            overflow = (((a & 0x8000) and not (b & 0x8000) and not (result & 0x8000)) or
                        (not (a & 0x8000) and   (b & 0x8000) and     (result & 0x8000)))
            return result, carry, overflow

class VM:
    def __init__(self, program: dict[int, int], initial_memory: dict[int, int] | None = None):
        self.regs: dict[Reg, int] = {r: 0x0000 for r in Reg}
        self.memory: dict[int, int] = {**program, **(initial_memory or {})}

        # Bookkeeping for debugging
        self.mem_read:    set[int] = set()
        self.mem_written: set[int] = set()
        self.reg_read:    set[Reg] = set()
        self.reg_written: set[Reg] = set()

        # Initialize PC to first instruction in program
        self.write_reg(Reg.pc, min(program.keys()))

    # Registers
    def read_reg(self, reg: Reg) -> int:
        if reg != Reg.rz:
            self.reg_read.add(reg)
        return self.regs.get(reg, 0x0000)

    def write_reg(self, reg: Reg, value: int):
        # Writing directly to fl is undefined behaviour but we allow it here
        if reg != Reg.rz:
            self.reg_written.add(reg)
            self.regs[reg] = value & 0xFFFF

    # Memory
    def read_mem(self, addr: int) -> int:
        self.mem_read.add(addr)
        return self.memory.get(addr, 0)

    def write_mem(self, addr: int, value: int):
        self.mem_written.add(addr)
        self.memory[addr] = value

    # Flags
    def get_flag(self, flag: Flags) -> bool:
        return bool((self.regs.get(Reg.fl, 0) >> flag) & 1)

    def update_flags(self, result: int, carry: bool = False, overflow: bool = False):
        """
        Updates architectural flags after an ALU operation.

        Z: Zero flag      (result == 0)
        N: Negative flag  (MSB set)
        C: Carry flag
        V: Overflow flag
        """
        fl  = (1 << Flags.Z) if (result & 0xFFFF) == 0 else 0
        fl |= (1 << Flags.N) if (result & 0x8000)      else 0
        fl |= (1 << Flags.C) if carry                  else 0
        fl |= (1 << Flags.V) if overflow               else 0
        self.write_reg(Reg.fl, fl)
    
    def condition_passes(self, cond: bool) -> bool:
        """
        Evaluates the instruction condition.

        In this ISA variant:
            cond == False  -> execute
            cond == True   -> only if Z flag is set
        """
        return (not cond) or self.get_flag(Flags.Z)

    # Executes a single instruction cycle. Returns False if execution should halt.
    def step(self) -> bool:
        pc   = self.regs.get(Reg.pc)
        word = self.memory.get(pc)

        if word is None:
            print(f"[vm] halt: no instruction at PC=0x{pc:04X}")
            return False

        instr = Instruction.from_word(word)
        if instr is None:
            print(f"[vm] halt: unknown opcode at PC=0x{pc:04X}  word=0x{word:04X}")
            return False

        print(f"  PC=0x{pc:04X}  {instr}")
        self.regs[Reg.pc] = (pc + 2) & 0xFFFF

        if self.condition_passes(instr.cond):
            self.execute(instr)
        return True

    ALU_OPS = (Opcode.AND, Opcode.ORR, Opcode.ADD, Opcode.SUB)

    # Actually executes the instruction by updating architectural state of the VM
    def execute(self, instr: Instruction):
        match instr.opcode:
            case Opcode.MOVL:
                self.write_reg(instr.rd, instr.imm8)
            case Opcode.SETH:
                self.write_reg(
                    instr.rd,
                    (instr.imm8 << 8) | (self.read_reg(instr.rd) & 0x00FF)
                )
            case Opcode.LDR:
                self.write_reg(instr.rd, self.read_mem(self.read_reg(instr.ra)))
            case Opcode.STR:
                self.write_mem(self.read_reg(instr.ra), self.read_reg(instr.rd))
            case _ if instr.opcode in self.ALU_OPS:
                result, carry, overflow = alu(
                    instr,
                    self.read_reg(instr.ra),
                    self.read_reg(instr.rb)
                )
                self.write_reg(instr.rd, result)
                self.update_flags(result, carry, overflow)

    def run(self):
        while self.step():
            pass

    def print_state(self):
        print("\n--- registers ---")
        for reg in Reg:
            if reg == Reg.rz:
                continue
            tags = access_tags(reg, self.reg_read, self.reg_written)

            if reg == Reg.fl:
                fl_val = self.regs.get(Reg.fl, 0)
                active = [f.name for f in Flags if (fl_val >> f) & 1]
                flags_str = ", ".join(active) if active else "none"
                print(f"  {reg.name:<4} = 0x{fl_val:04X}  ({flags_str})  {tags}")
            else:
                print(f"  {reg.name:<4} = 0x{self.regs.get(reg, 0):04X}  {tags}")

        all_mem = sorted(self.mem_read | self.mem_written)
        if all_mem:
            print("\n--- accessed memory ---")
            for addr in all_mem:
                tags = access_tags(addr, self.mem_read, self.mem_written)
                print(f"  [0x{addr:04X}] = 0x{self.memory.get(addr, 0):04X}  {tags}")
