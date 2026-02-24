# Straight Line of Hell

The provided `script.py` gives insight into how the symmetric cipher operates internally:
```
# note to self
# [b00, b01, b02, b03, ...] [b0]
# [b10, b11, b12, b13, ...] [b1]
# [b20, b21, b22, b23, ...] [b2]
# [b30, b31, b32, b33, ...] [b3]
# [ :    :    :    :   '. ] [:]

def func1(p_0):
    local_0 = p_0.shape[0]
    local_1 = p_0.copy() % 2
    local_2 = np.identity(local_0, dtype=int)

    local_3 = np.concatenate((local_1, local_2), axis=1)
    
    for local_4 in range(local_0):
        local_5 = -1
        for local_6 in range(local_4, local_0):
            if local_3[local_6, local_4] == 1:
                local_5 = local_6
                break
        if local_5 == -1:
            raise ValueError("?????")
        if local_5 != local_4:
            local_3[[local_4, local_5]] = local_3[[local_5, local_4]]
        for local_6 in range(local_0):
            if local_6 != local_4 and local_3[local_6, local_4] == 1:
                local_3[local_6] ^= local_3[local_4]
    local_7 = local_3[:, local_0:]
    return local_7
```

From the source code, it is clear that the function computes the inverse of a matrix over GF(2). It first reduces all entries modulo 2, ensuring that the matrix elements lie within the field GF(2). It then constructs an augmented matrix by concatenating the original matrix with the identity matrix and performs Gaussian elimination to obtain the inverse. Only row swaps and XOR operations are used so the reduction remains closed over GF(2).

The comments at the top suggest that encryption is performed via matrix multiplication over GF(2). In other words, the cipher likely encrypts a 32-bit plaintext block 'x' by multiplying it with a fixed 32×32 binary matrix 'A' used as the private key to get each 32-bit block of the ciphertext 'y'.

$$
y = A x  \quad \text{over } \mathrm{GF}(2),
$$



Since the encryption appears to be linear over GF(2), we can recover the encryption matrix by querying the oracle with basis vectors. If we encrypt each 32-bit unit vector , the resulting ciphertext corresponds to one column of the encryption matrix. Repeating this process for all 32 bit positions allows us to reconstruct the entire private key.

Once the matrix is recovered, it is pretty straightforward to decrypt the ciphertext using the provided inverse function applied on the ciphertext. 
$$
x = A^{-1} y  \quad \text{over } \mathrm{GF}(2),
$$


Thus using `solve.py` we get the flag.
```bash
./solve.py
disorientation{l*ne4r1ty-iS-a-cuuuurs3!}
```














