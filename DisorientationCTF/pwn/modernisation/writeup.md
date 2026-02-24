# modernisation

The given program is an interesting mesh between two languages. The `main.rs` file reads user input and calculates its length, while `bank_checker.c` performs validation against that input and prints the balance if necessary. 

The primary vulnerability arises from how the Rust program calculates the `len` parameter passed to the `bank_checker()` function. It uses `len = input.chars().count();`, which counts **Unicode codepoints** rather than the actual number of bytes. This is important because a single Unicode character can occupy multiple bytes (up to 4). As a result, the length passed to the C function does not necessarily match the actual byte length of the input.

Since the `give_balance()` trusts the `len` is correct, `strcpy()` now allows a buffer overflow on its stack buffer `char my_copy[20]` so we can ovewrite adjacent stack variables. 

Remember that our goal is to discover ZOOWEE's bank balance so to do that we must trigger both the `memcmp(my_copy, correct_username)` and the `ADMIN_ALLOWED` checks. 

To understand how the payload is constructed, we can examine the stack frame:
```asm
ebp-0x2b (-43): my_copy[20]       <- strcpy writes here
ebp-0x17 (-23): correct_username  <- only 20 bytes after my_copy!
ebp-0x10 (-16): ADMIN_ALLOWED     <- 27 bytes after my_copy
```

<pre>
Higher memory addresses
+-------------------------+
| ADMIN_ALLOWED (int)     |  <- controls admin access
+-------------------------+
| correct_username[7]     |  <- compared with memcmp
+-------------------------+
| my_copy[20]             |  <- strcpy destination
+-------------------------+
| saved EBP               |
+-------------------------+
| return address          |
Lower memory addresses
</pre>

Or as viewed in GDB:
```bash
./gdb bank_checkernew 
b give_balance
r
# Trigger the breakpoint with a username
a
(gdb) p &my_copy
$1 = (char (*)[20]) 0xffffc84d
(gdb) p &correct_username
$2 = (char (*)[7]) 0xffffc861
(gdb) p &ADMIN_ALLOWED
$3 = (int *) 0xffffc868
```

These addresses show that `correct_username` sits immediately above `my_copy`, with `ADMIN_ALLOWED` directly after it. This means that any overflow from `my_copy` will first overwrite `correct_username` before reaching the admin flag.

This creates an additional constraint when building the payload. Even if we successfully overwrite `ADMIN_ALLOWED`, the `memcmp()` check will fail if `correct_username` has been corrupted. Because of this, the payload must not only set `ADMIN_ALLOWED` to a nonzero value, but also restore `correct_username` to the expected string.

Thus the payload consists of 4 parts:
1. Provide a username 
2. Add unicode characters to fill the buffer
3. Overwrite the `correct_username` to match our given username
4. Overwrite `ADMIN_ALLOWED` to any non-zero value (`TRUE`)

```bash
./solve.py REMOTE
b'ADMIN mode enabled. Logged in as ZOOWEEAA\nYou have 407314488 dollars in your bank account\n'
```



