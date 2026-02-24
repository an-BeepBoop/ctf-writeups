
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