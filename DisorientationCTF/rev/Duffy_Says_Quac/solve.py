#!/usr/bin/env python3
from quac_assembler import parse_file
from vm import VM

program = parse_file("mystery.txt")
vm = VM(program, initial_memory={0xF0: 0xFADE})
vm.run()
vm.print_state()
