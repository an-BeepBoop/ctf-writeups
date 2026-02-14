# reflection

Looks like the binary is just a rust program that calls `panic()`. Clearly, the author has injected some code into the program recovery state that validates the flag.


--- 
Some context:

When an application throws an exception, the program does not stop abruptly. Instead, it enters a recovery phase known as stack unwinding (or, in some configurations, terminates immediately in **abort** mode).

[EH_FRAME DOCS](https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html)
Stack unwinding requires the runtime environment to traverse the call stack until an exception handler has been found. The runtime manages stack unwinding by storing metadata that describes the layout of the stack. This metadata resides in the `_eh_frame` (Exception Handling Frame) section of the ELF binary, effectively serving as a lookup table for unwinding operations.

More specifically, the `.eh_frame` section contains DWARF Call Frame Information (CFI). 

[DWARF DOCS](https://dwarfstd.org/doc/DWARF5.pdf)
> DWARF is a debugging information file format used by many compilers and debuggers to support source level debugging. It addresses the requirements of a number of procedural languages, such as C, C++, and Fortran, and is designed to be extensible to other languages. DWARF is architecture independent and applicable to any processor or operating system. It is widely used on Unix, Linux and other operating systems, as well as in stand-alone environments.

This information instructs the unwinder on how to restore registers and locate the previous stack frame. When `panic!()` is triggered, it initiates stack unwinding, which in turn evaluates the DWARF expressions in `.eh_frame`. The author has embedded a complete validation routine within these expressions, making the unwinding process itself a part of the program’s hidden logic.

Each DWARF CFI record consists of:
* **One Common Information Entry (CIE)**
* **One or more Frame Description Entries (FDEs)**
Both CIEs and FDEs must be aligned to an address-unit-sized boundary.

### Common Information Entry (CIE) — a template shared across multiple functions

| Field                  | Description                                                                                       |
|------------------------|---------------------------------------------------------------------------------------------------|
| Augmentation String    | Feature flags indicating additional functionality, e.g., `"zR"` for basic, `"zPLR"` for personality function |
| Code Alignment Factor  | Multiplier for instruction alignment (typically 1 on x86-64)                                      |
| Data Alignment Factor  | Multiplier for stack slot size (typically -8 on x86-64)                                          |
| Return Address Register| Register storing the return address (16 = RIP on x86-64)                                         |
| Initial Instructions   | Default CFI rules inherited by all associated FDEs                                               |

### Frame Description Entry (FDE) — one per function

| Field                   | Description                                                          |
| ----------------------- | -------------------------------------------------------------------- |
| PC Begin                | Starting address of the function                                     |
| PC Range                | Function size in bytes                                               |
| Call Frame Instructions | CFI bytecode describing how the stack frame changes during execution |


[STACK UNWINDING](https://os.phil-opp.com/freestanding-rust-binary/)
```
// Summary of libgcc/unwind.inc
_Unwind_RaiseException(exc) {
    // Phase 1 — Search:
    //   Walk frames upward looking for a handler (catch_unwind).
    //   Nothing is modified yet. Expressions execute but results are discarded.
    while (1) {
        uw_frame_state_for(&context, &fs);   // parse CFI, find FDE
        if (fs.personality)
            personality(..._UA_SEARCH_PHASE...);  // Query: cleanup? catch?
        uw_update_context(&context, &fs);     // Apply CFI rules
    }

    cur_context = this_context;  // ★ Reset to initial state

    // Phase 2 — Cleanup:
    //   Walk frames again from the beginning.
    //   At each frame: restore registers, run cleanup code.
    //   When the handler frame is reached, jump to it.
    while (1) {
        uw_frame_state_for(&context, &fs);
        if (fs.personality)
            personality(..._UA_CLEANUP_PHASE...);
        uw_update_context(&context, &fs);     // ★ Execute expressions, determine RIP
    }
}
```

`uw_update_context()` parses CFI rules from `.eh_frame` and determines the register values for the previous stack frame. When a rule contains a DWARF expression, it calls `execute_stack_op()`, a stack-based bytecode VM implemented in libgcc.

Because both phases walk the same stack frames, every DWARF expression gets executed twice—once in each phase. Phase 1, however, resets the context afterward, so only the results from Phase 2 are ultimately significant.

### TODO 

```
lactf{sike_this_is_actually_a_pumber_reference}
```


