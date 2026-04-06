#!/usr/bin/env python3

# Solve script lifted from https://github.com/anucssa/disorientation-ctf-2026-public/blob/main/challenges/rev/traitor/solution/soln.py#L3

import z3
from collections import defaultdict
import string
import re
# Define functions that refer to traits CA, CB, CC, CD, CE.
# CA is implemented on single structs
# CB, CE is implemented on Op2
# CC, CD is implemented on Op3
# We can encode the "implemented-ness" of structs and traits as functions.
# For example, the "CA" function takes an int (representing one of the number structs)
# and returns if it implements CA.
ca = z3.Function("CA", z3.IntSort(), z3.BoolSort())
cb = z3.Function("CB", z3.IntSort(), z3.IntSort(), z3.BoolSort())
cc = z3.Function("CC", z3.IntSort(), z3.IntSort(), z3.IntSort(), z3.BoolSort())
cd = z3.Function("CD", z3.IntSort(), z3.IntSort(), z3.IntSort(), z3.BoolSort())
ce = z3.Function("CE", z3.IntSort(), z3.IntSort(), z3.BoolSort())

# Get file contents for regex searching later.
with open("main.rs") as file:
    contents = file.read()

# Define z3 numbers
z3_nums = {
    "Zero": z3.IntVal(0),
    "One": z3.IntVal(1),
    "Two": z3.IntVal(2),
    "Three": z3.IntVal(3),
    "Four": z3.IntVal(4),
    "Five": z3.IntVal(5),
    "Six": z3.IntVal(6),
    "Seven": z3.IntVal(7),
    "Eight": z3.IntVal(8),
    "Nine": z3.IntVal(9),
    "Ten": z3.IntVal(10),
}
solver = z3.Solver()

# Extract CA, CB, CC, CD and CE implementations using regex
ca_implementors = re.findall("impl CA for (\\b\\w+\\b) {}", contents)
cb_implementors = re.findall("impl CB for Op2<(\\b\\w+\\b), (\\b\\w+\\b)> {}", contents)
cc_implementors = re.findall("impl CC for Op3<(\\b\\w+\\b), (\\b\\w+\\b), (\\b\\w+\\b)> {}", contents)
cd_implementors = re.findall("impl CD for Op3<(\\b\\w+\\b), (\\b\\w+\\b), (\\b\\w+\\b)> {}", contents)
ce_implementors = re.findall("impl CE for Op2<(\\b\\w+\\b), (\\b\\w+\\b)> {}", contents)
# Convert these strings into assertions. Our goal here is to form definitions for all 5 functions.
# We construct sum of products (disjunctive normal forms for all 5 functions).
# This means for example if CA is implemented for 0, 3, 6, 9 then the definition
# would be
# forall x, ca(x) == ((x == 0) or (x == 3) or (x == 6) or (x == 9))
# This way all other inputs for the function return false.
x = z3.Int('x')
y = z3.Int('y')
z = z3.Int('z')
ca_assertions = []
cb_assertions = []
cc_assertions = []
cd_assertions = []
ce_assertions = []
for implementing_int in ca_implementors:
    value = z3_nums[implementing_int]
    ca_assertions.append(x == value)
for (a, b) in cb_implementors:
    a = z3_nums[a]
    b = z3_nums[b]
    cb_assertions.append(z3.And((x == a), (y == b)))
for (a, b) in ce_implementors:
    a = z3_nums[a]
    b = z3_nums[b]
    ce_assertions.append(z3.And((x == a), (y == b)))
for (a, b, c) in cc_implementors:
    a = z3_nums[a]
    b = z3_nums[b]
    c = z3_nums[c]
    cc_assertions.append(z3.And((x == a), (y == b), (z == c)))
for (a, b, c) in cd_implementors:
    a = z3_nums[a]
    b = z3_nums[b]
    c = z3_nums[c]
    cd_assertions.append(z3.And((x == a), (y == b), (z == c)))
# Add the assertions to the solver
solver.add(z3.ForAll(x, ca(x) == z3.Or(*ca_assertions)))
solver.add(z3.ForAll([x, y], cb(x, y) == z3.Or(*cb_assertions)))
solver.add(z3.ForAll([x, y], ce(x, y) == z3.Or(*ce_assertions)))
solver.add(z3.ForAll([x, y, z], cc(x, y, z) == z3.Or(*cc_assertions)))
solver.add(z3.ForAll([x, y, z], cd(x, y, z) == z3.Or(*cd_assertions)))
# a_to_z contains our Z3 integers to solve for.
a_to_z = [z3.Int(name) for name in string.ascii_uppercase]
# Extract the constraints on the `Question` struct.
op1_requirements = re.findall("([A-Z]): (\\b\\w+\\b)", contents)
op2_requirements = re.findall("Op2<([A-Z]), ([A-Z])>: (\\b\\w+\\b)", contents)
op3_requirements = re.findall("Op3<([A-Z]), ([A-Z]), ([A-Z])>: (\\b\\w+\\b)", contents)
# Add the requirements to the solver.
for (letter, _) in op1_requirements:
    # its definitely CA
    solver.add(ca(a_to_z[string.ascii_uppercase.find(letter)]) == True)
    pass
for (a, b, target) in op2_requirements:
    # CB or CE
    a = a_to_z[string.ascii_uppercase.find(a)]
    b = a_to_z[string.ascii_uppercase.find(b)]
    if target == "CB":
        target_f = cb
    elif target == "CE":
        target_f = ce
    solver.add(target_f(a, b) == True)
for (a, b, c, target) in op3_requirements:
    # CC or CD
    a = a_to_z[string.ascii_uppercase.find(a)]
    b = a_to_z[string.ascii_uppercase.find(b)]
    c = a_to_z[string.ascii_uppercase.find(c)]
    if target == "CC":
        target_f = cc
    elif target == "CD":
        target_f = cd
    solver.add(target_f(a, b, c) == True)

# Make sure its SAT (satisfiable)
print(solver.check())
model = solver.model()
# Get integers in sorted order
integer_values = map(lambda int_obj: str(model[int_obj]), a_to_z)
# Join into flag
joined_string = ','.join(integer_values)
flag = f"disorientation{{{joined_string}}}"
# Got the flag!
print(flag)

import z3
from collections import defaultdict
import string
import re
# Define functions that refer to traits CA, CB, CC, CD, CE.
# CA is implemented on single structs
# CB, CE is implemented on Op2
# CC, CD is implemented on Op3
# We can encode the "implemented-ness" of structs and traits as functions.
# For example, the "CA" function takes an int (representing one of the number structs)
# and returns if it implements CA.
ca = z3.Function("CA", z3.IntSort(), z3.BoolSort())
cb = z3.Function("CB", z3.IntSort(), z3.IntSort(), z3.BoolSort())
cc = z3.Function("CC", z3.IntSort(), z3.IntSort(), z3.IntSort(), z3.BoolSort())
cd = z3.Function("CD", z3.IntSort(), z3.IntSort(), z3.IntSort(), z3.BoolSort())
ce = z3.Function("CE", z3.IntSort(), z3.IntSort(), z3.BoolSort())

# Get file contents for regex searching later.
with open("main.rs") as file:
    contents = file.read()

# Define z3 numbers
z3_nums = {
    "Zero": z3.IntVal(0),
    "One": z3.IntVal(1),
    "Two": z3.IntVal(2),
    "Three": z3.IntVal(3),
    "Four": z3.IntVal(4),
    "Five": z3.IntVal(5),
    "Six": z3.IntVal(6),
    "Seven": z3.IntVal(7),
    "Eight": z3.IntVal(8),
    "Nine": z3.IntVal(9),
    "Ten": z3.IntVal(10),
}
solver = z3.Solver()

# Extract CA, CB, CC, CD and CE implementations using regex
ca_implementors = re.findall("impl CA for (\\b\\w+\\b) {}", contents)
cb_implementors = re.findall("impl CB for Op2<(\\b\\w+\\b), (\\b\\w+\\b)> {}", contents)
cc_implementors = re.findall("impl CC for Op3<(\\b\\w+\\b), (\\b\\w+\\b), (\\b\\w+\\b)> {}", contents)
cd_implementors = re.findall("impl CD for Op3<(\\b\\w+\\b), (\\b\\w+\\b), (\\b\\w+\\b)> {}", contents)
ce_implementors = re.findall("impl CE for Op2<(\\b\\w+\\b), (\\b\\w+\\b)> {}", contents)
# Convert these strings into assertions. Our goal here is to form definitions for all 5 functions.
# We construct sum of products (disjunctive normal forms for all 5 functions).
# This means for example if CA is implemented for 0, 3, 6, 9 then the definition
# would be
# forall x, ca(x) == ((x == 0) or (x == 3) or (x == 6) or (x == 9))
# This way all other inputs for the function return false.
x = z3.Int('x')
y = z3.Int('y')
z = z3.Int('z')
ca_assertions = []
cb_assertions = []
cc_assertions = []
cd_assertions = []
ce_assertions = []
for implementing_int in ca_implementors:
    value = z3_nums[implementing_int]
    ca_assertions.append(x == value)
for (a, b) in cb_implementors:
    a = z3_nums[a]
    b = z3_nums[b]
    cb_assertions.append(z3.And((x == a), (y == b)))
for (a, b) in ce_implementors:
    a = z3_nums[a]
    b = z3_nums[b]
    ce_assertions.append(z3.And((x == a), (y == b)))
for (a, b, c) in cc_implementors:
    a = z3_nums[a]
    b = z3_nums[b]
    c = z3_nums[c]
    cc_assertions.append(z3.And((x == a), (y == b), (z == c)))
for (a, b, c) in cd_implementors:
    a = z3_nums[a]
    b = z3_nums[b]
    c = z3_nums[c]
    cd_assertions.append(z3.And((x == a), (y == b), (z == c)))
# Add the assertions to the solver
solver.add(z3.ForAll(x, ca(x) == z3.Or(*ca_assertions)))
solver.add(z3.ForAll([x, y], cb(x, y) == z3.Or(*cb_assertions)))
solver.add(z3.ForAll([x, y], ce(x, y) == z3.Or(*ce_assertions)))
solver.add(z3.ForAll([x, y, z], cc(x, y, z) == z3.Or(*cc_assertions)))
solver.add(z3.ForAll([x, y, z], cd(x, y, z) == z3.Or(*cd_assertions)))
# a_to_z contains our Z3 integers to solve for.
a_to_z = [z3.Int(name) for name in string.ascii_uppercase]
# Extract the constraints on the `Question` struct.
op1_requirements = re.findall("([A-Z]): (\\b\\w+\\b)", contents)
op2_requirements = re.findall("Op2<([A-Z]), ([A-Z])>: (\\b\\w+\\b)", contents)
op3_requirements = re.findall("Op3<([A-Z]), ([A-Z]), ([A-Z])>: (\\b\\w+\\b)", contents)
# Add the requirements to the solver.
for (letter, _) in op1_requirements:
    # its definitely CA
    solver.add(ca(a_to_z[string.ascii_uppercase.find(letter)]) == True)
    pass
for (a, b, target) in op2_requirements:
    # CB or CE
    a = a_to_z[string.ascii_uppercase.find(a)]
    b = a_to_z[string.ascii_uppercase.find(b)]
    if target == "CB":
        target_f = cb
    elif target == "CE":
        target_f = ce
    solver.add(target_f(a, b) == True)
for (a, b, c, target) in op3_requirements:
    # CC or CD
    a = a_to_z[string.ascii_uppercase.find(a)]
    b = a_to_z[string.ascii_uppercase.find(b)]
    c = a_to_z[string.ascii_uppercase.find(c)]
    if target == "CC":
        target_f = cc
    elif target == "CD":
        target_f = cd
    solver.add(target_f(a, b, c) == True)

# Make sure its SAT (satisfiable)
print(solver.check())
model = solver.model()
# Get integers in sorted order
integer_values = map(lambda int_obj: str(model[int_obj]), a_to_z)
# Join into flag
joined_string = ','.join(integer_values)
flag = f"disorientation{{{joined_string}}}"
# Got the flag!
print(flag)
