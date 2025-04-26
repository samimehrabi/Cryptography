def rotate_left(val, r_bits, max_bits):
    return ((val << r_bits) | (val >> (max_bits - r_bits))) & ((1 << max_bits) - 1)


mini_sbox = [0x6, 0x4, 0xC, 0x5,
             0x0, 0x7, 0x2, 0xE,
             0x1, 0xF, 0x3, 0xD,
             0x8, 0xA, 0x9, 0xB]


def apply_mini_sbox32(x):
    result = 0
    for i in range(0, 32, 4):
        nibble = (x >> i) & 0xF
        result |= (mini_sbox[nibble] << i)
    return result

def feistel_round32(r, subkey32):
    temp = (r ^ subkey32) & 0xFFFFFFFF
    temp = rotate_left(temp, 4, max_bits=32)
    temp = apply_mini_sbox32(temp)
    return temp


def simple_feist_encrypt(block, key):
   
    L = (block >> 32) & 0xFFFFFFFF
    R = block & 0xFFFFFFFF
    for i in range(1, 11):
        
        rot64 = rotate_left(key, i, max_bits=64)
        subkey32 = rot64 & 0xFFFFFFFF
        f_out = feistel_round32(R, subkey32)
        L, R = R, L ^ f_out
    
    return (L << 32) | R


def simple_feist_decrypt(ciphertext, key):
  
    L = (ciphertext >> 32) & 0xFFFFFFFF
    R = ciphertext & 0xFFFFFFFF
    for i in reversed(range(1, 11)):
        rot64 = rotate_left(key, i, max_bits=64)
        subkey32 = rot64 & 0xFFFFFFFF
        prev_L = R ^ feistel_round32(L, subkey32)
        prev_R = L
        L, R = prev_L, prev_R
    return (L << 32) | R


plaintext  = 0x0123456789ABCDEF
key        = 0x0F1571C947D9E859
ciphertext = simple_feist_encrypt(plaintext, key)
decrypted  = simple_feist_decrypt(ciphertext, key)

print(f"Plaintext  : {plaintext:#018x}")
print(f"Ciphertext : {ciphertext:#018x}")
print(f"Decrypted  : {decrypted:#018x}")
