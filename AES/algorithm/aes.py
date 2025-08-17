# AES-128 Implementation (Pure Python, chuẩn NIST)
import hashlib

def normalize_key(key_str, size=16):
    key_bytes = hashlib.sha256(key_str.encode()).digest()
    return key_bytes[:size] 

Nb = 4
Nk = 4
Nr = 10

Sbox = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]

InvSbox = [0]*256
for i in range(256):
    InvSbox[Sbox[i]] = i

Rcon = [0x01000000,0x02000000,0x04000000,0x08000000,
        0x10000000,0x20000000,0x40000000,0x80000000,
        0x1b000000,0x36000000]

def sub_word(word):
    return ((Sbox[(word >> 24) & 0xFF] << 24) |
            (Sbox[(word >> 16) & 0xFF] << 16) |
            (Sbox[(word >> 8) & 0xFF] << 8) |
            (Sbox[word & 0xFF]))

def rot_word(word):
    return ((word << 8) & 0xFFFFFFFF) | ((word >> 24) & 0xFF)

def key_expansion(key):
    assert len(key) == 16, "Key phải đúng 16 byte cho AES-128"
    w = [0]*Nb*(Nr+1)
    for i in range(Nk):
        w[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3]
    for i in range(Nk, Nb*(Nr+1)):
        temp = w[i-1]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp)) ^ Rcon[i//Nk -1]
        w[i] = w[i-Nk] ^ temp
    return w

def add_round_key(state, w, round):
    for col in range(Nb):
        word = w[round*Nb+col]
        for row in range(4):
            state[row][col] ^= (word >> (24 - 8*row)) & 0xFF

def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = Sbox[state[r][c]]

def inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = InvSbox[state[r][c]]

def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def inv_shift_rows(state):
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]

def xtime(a):
    return ((a<<1) ^ 0x1B) & 0xFF if (a & 0x80) else (a<<1)

def mul(a,b):
    res = 0
    for i in range(8):
        if b & 1:
            res ^= a
        a = xtime(a)
        b >>= 1
    return res

def mix_columns(state):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = mul(a[0],2) ^ mul(a[1],3) ^ a[2] ^ a[3]
        state[1][c] = a[0] ^ mul(a[1],2) ^ mul(a[2],3) ^ a[3]
        state[2][c] = a[0] ^ a[1] ^ mul(a[2],2) ^ mul(a[3],3)
        state[3][c] = mul(a[0],3) ^ a[1] ^ a[2] ^ mul(a[3],2)

def inv_mix_columns(state):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = mul(a[0],14) ^ mul(a[1],11) ^ mul(a[2],13) ^ mul(a[3],9)
        state[1][c] = mul(a[0],9) ^ mul(a[1],14) ^ mul(a[2],11) ^ mul(a[3],13)
        state[2][c] = mul(a[0],13) ^ mul(a[1],9) ^ mul(a[2],14) ^ mul(a[3],11)
        state[3][c] = mul(a[0],11) ^ mul(a[1],13) ^ mul(a[2],9) ^ mul(a[3],14)

def encrypt_block(input_bytes, w):
    assert len(input_bytes) == 16
    state = [[0]*Nb for _ in range(4)]
    for r in range(4):
        for c in range(Nb):
            state[r][c] = input_bytes[r+4*c]

    add_round_key(state,w,0)
    for rnd in range(1,Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state,w,rnd)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state,w,Nr)

    output = [0]*16
    for r in range(4):
        for c in range(4):
            output[r+4*c] = state[r][c]
    return bytes(output)

def decrypt_block(input_bytes, w):
    assert len(input_bytes) == 16
    state = [[0]*Nb for _ in range(4)]
    for r in range(4):
        for c in range(Nb):
            state[r][c] = input_bytes[r+4*c]

    add_round_key(state,w,Nr)
    for rnd in range(Nr-1,0,-1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state,w,rnd)
        inv_mix_columns(state)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state,w,0)

    output = [0]*16
    for r in range(4):
        for c in range(4):
            output[r+4*c] = state[r][c]
    return bytes(output)

def pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_aes(plaintext: str, key_str: str):
    key = normalize_key(key_str, 16)
    w = key_expansion(list(key))
    data = plaintext.encode()
    data = pad(data, 16)

    out = b""
    for i in range(0, len(data), 16):
        out += encrypt_block(data[i:i+16], w)
    return out.hex()

def decrypt_aes(ciphertext_hex: str, key_str: str):
    key = normalize_key(key_str, 16)
    w = key_expansion(list(key))
    data = bytes.fromhex(ciphertext_hex)

    out = b""
    for i in range(0, len(data), 16):
        out += decrypt_block(data[i:i+16], w)
    return unpad(out).decode()
