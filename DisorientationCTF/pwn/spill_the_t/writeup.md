## spill the t

The given `vuln` binary implements a simple gossip management system backed by heap allocations.

The user can:

* `spill_tea()` — Allocates a structure and stores gossip text
* `hear_tea()` — Displays active gossip entries
* `update_tea()` — Modifies existing gossip content
* `remove_tea()` — Removes a gossip entry
* `exit_tea()` — Exits the program

There is also a hidden helper function `print_flag()` which leaks the flag if invoked indirectly through control flow hijacking.


---

## Diagnostics


```bash
checksec file vuln
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    Stripped:   No

strings libc.so.6 | grep GLIBC_
```

The checksec flags indicate:

* No PIE → global symbols such as GOT entries are located at fixed addresses
* NX enabled → direct shellcode injection is not feasible
* No stack canary → stack overflow mitigation is absent, though the primary exploit targets the heap

The libc version is glibc 2.39. Therefore, the allocator behaviour is follows the tcache implementation, including freelist caching and absence of global bin coalescing. 


---

The program maintains a linked list of gossip entries using the following structure:

```c
typedef struct tea {
    unsigned int active;
    struct tea* next;
    char* tea;
} tea_t;
```

Each node consists of metadata, a pointer to the next node, and a pointer to a separately allocated 48-byte buffer storing the gossip content.

---

### Vulnerabilities

The primary vulnerability arises from a **use-after-free (UAF)** condition caused by improper pointer lifetime management.

When `remove_tea()` is called, the program performs the following operations:

1. Marks the node as inactive by setting `active = 0`
2. Frees the gossip content buffer (`tea->tea`)
3. Frees the node structure itself

However, the program does not nullify the pointer stored in the global list head `spilled_tea`. As a result, `spilled_tea` continues pointing to freed heap memory, creating a dangling pointer reference.

Additionally, the linked list traversal logic does not verify node validity beyond pointer chain checks, allowing traversal into freed memory regions.

The critical flaw lies in the `update_tea()` function.

Although nodes may be freed, `update_tea()` does not check the `active` flag before writing data.

This allows writing user-controlled data into memory regions that have already been returned to the allocator, enabling heap metadata and freelist pointer corruption.

---

### Exploit Strategy

The exploit leverages **tcache poisoning** combined with a UAF write primitive to achieve arbitrary memory write.

The heap layout and attack sequence are carefully controlled.

Each gossip entry allocation consists of:

* A `tea_t` node structure (24 bytes), which is served from the `tcache[32]` bin.
* A gossip content buffer (48 bytes), which is served from the `tcache[64]` bin.

The key observation is that glibc free() operations write metadata into freed chunks:

* The forward pointer (`fd`) is stored at `data[0]`
* A tcache security key may be stored at `data[8]` depending on allocator configuration
* The pointer stored at offset 16 (the `tea*` pointer) remains intact after free and can be abused.

---

#### Step 1. Heap Population

Two gossip entries are created using `spill_tea()`, generating:

* Node A and content B
* Node C and content D

This ensures tcache bins for sizes 32 and 64 are populated.

---

#### Step 2. Inducing Use-After-Free

The first entry is removed:

* `remove(1)` frees node D and node C, placing them into tcache.

Then the second entry is removed:

* `remove(0)` frees node B and node A.

Importantly, `spilled_tea` still points to node A after deletion, creating a dangling pointer.

---

#### Step 3. Tcache Poisoning

Using the UAF primitive in `update_tea()`, the exploit writes a controlled value into the freed chunk.

The attack overwrites the forward pointer inside the tcache freelist entry:

```
fd → PUTS_GOT
```

This manipulates the allocator such that subsequent allocations will return controlled memory regions.

---

#### Step 4. GOT Hijacking

Subsequent allocations are used to drain the poisoned tcache entry.

When a chunk is allocated from the corrupted freelist:

1. The allocator returns a chunk pointing to `puts@GOT`.
2. User input is written into this location.

Since PIE is disabled, global offsets are fixed and can be directly targeted.

The exploit overwrites the GOT entry of `puts()` with the address of `print_flag()`.

---

#### Step 5. Triggering the Flag Leak

When the program later invokes `puts()`, control flow is redirected to `print_flag()`, causing the flag to be printed.

---

### Final Exploit

Thus the final exploit is as follows:

1. Populate heap with two gossip nodes.
2. Delete both nodes to place chunks into tcache bins.
3. Use UAF write to poison the freelist pointer.
4. Force allocations to return a pointer to the GOT entry of `puts()`.
5. Overwrite `puts@GOT` with the address of `print_flag()`.
6. Trigger the overwritten GOT entry to leak the flag.


```bash
./solve.py REMOTE
disorientation{Ch3ck_l1nKtr3e_1n_bi0}
```
