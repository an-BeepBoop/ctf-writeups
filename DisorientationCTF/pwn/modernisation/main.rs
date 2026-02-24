unsafe extern "C" {
    unsafe fn give_balance(ptr: *const u8, len: std::ffi::c_int);
}

fn main() {
    println!("Please enter your username");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
    input = input.trim().to_string();
    input += "\0"; // add null byte just in case
    let len = input.chars().count();
    // Call legacy C code
    // Unsafe marking needed but we precompute len and stuff to prevent c
    // null byte problems with strlen so its safe.
    unsafe {
        give_balance(input.as_ptr(), len as std::ffi::c_int);
    };
}
