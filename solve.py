#!/usr/bin/env python3
"""
Solver — Mooncrust: Deep Space Recon (MNC-SPN-16)
Target : https://adventuremnc.mooncrust.my.id
Flag   : KTCG{...}

Membalik SPN 4-ronde (AddRoundKey -> SubBytes -> Diffuse) untuk memulihkan
16-byte key dari target signature, lalu mendekripsi payload 51-byte
menggunakan keystream SHA-256 counter mode.
"""
import hashlib

# ---- Parameter diambil verbatim dari bundle.js (class `ui`) ----
Gc = [99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22]  # AES S-box
inv_sbox = [0]*256
for i, v in enumerate(Gc):
    inv_sbox[v] = i

Hc = [  # 4 round key konstan
    [58,92,113,158,18,68,136,187,35,103,171,239,1,69,137,205],
    [119,25,66,168,83,209,15,107,156,62,132,42,254,97,181,7],
    [145,40,254,67,106,124,49,213,130,11,78,169,21,236,100,61],
    [79,178,6,141,202,57,151,30,88,225,44,112,180,99,173,90],
]
Wc = [48,54,62,52,225,2,236,229,15,191,201,127,29,112,167,122]  # target signature
ss = [249,166,40,12,180,41,42,236,128,53,68,252,212,92,251,212,49,114,173,23,10,142,194,29,99,128,43,138,231,73,249,234,6,75,2,91,215,189,210,47,229,221,103,231,79,25,59,225,192,235,146]  # ciphertext (51 byte)


def rotl8(x):
    return ((x << 3) | (x >> 5)) & 255


def diffuse(e):
    t = [0]*16
    for n in range(16):
        t[n] = rotl8(e[n]) ^ e[(n+1) % 16] ^ e[(n+5) % 16]
    return t


# ---- Bangun matriks GF(2) 128x128 untuk diffuse, lalu inverskan ----
def st2bits(st):
    v = 0
    for n in range(16):
        for b in range(8):
            if (st[n] >> b) & 1:
                v |= 1 << (n*8 + b)
    return v


def bits2st(v):
    st = [0]*16
    for k in range(128):
        if (v >> k) & 1:
            st[k // 8] |= 1 << (k % 8)
    return st


cols = []
for j in range(128):
    st = [0]*16
    st[j // 8] |= 1 << (j % 8)
    cols.append(st2bits(diffuse(st)))

A = [0]*128                                  # A[i] bit-j = (col[j] >> i) & 1
for j in range(128):
    c = cols[j]
    for i in range(128):
        if (c >> i) & 1:
            A[i] |= 1 << j

M = [A[i] | (1 << (128+i)) for i in range(128)]   # augment dengan identitas
for col in range(128):
    piv = next(r for r in range(col, 128) if (M[r] >> col) & 1)
    M[col], M[piv] = M[piv], M[col]
    for r in range(128):
        if r != col and ((M[r] >> col) & 1):
            M[r] ^= M[col]
mask = (1 << 128) - 1
Ainv = [(M[i] >> 128) & mask for i in range(128)]


def inv_diffuse(st):
    y = st2bits(st)
    x = 0
    for i in range(128):
        if bin(Ainv[i] & y).count('1') & 1:
            x |= 1 << i
    return bits2st(x)


def transform(key):
    t = list(key)
    for n in range(4):
        for a in range(16):
            t[a] ^= Hc[n][a]          # AddRoundKey
            t[a] = Gc[t[a]]           # SubBytes
        t = diffuse(t)                # Diffuse
    return t


def inv_transform(out):
    t = list(out)
    for n in range(3, -1, -1):
        t = inv_diffuse(t)                    # inverse Diffuse
        for a in range(16):
            t[a] = inv_sbox[t[a]]             # inverse SubBytes
            t[a] ^= Hc[n][a]                  # inverse AddRoundKey
    return t


def decrypt(key):
    ks = bytearray()
    n = 0
    while len(ks) < len(ss):
        ctr = bytes([(n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255])
        ks += hashlib.sha256(bytes(key) + ctr).digest()
        n += 1
    return bytes(ss[i] ^ ks[i] for i in range(len(ss)))


if __name__ == "__main__":
    key = inv_transform(Wc)
    assert transform(key) == Wc, "SPN inversion self-check FAILED"
    print("Recovered key (hex)  :", ''.join(f'{b:02x}' for b in key))
    print("Recovered key (ascii):", bytes(key).decode('ascii', 'replace'))
    print("FLAG                 :", decrypt(key).decode('utf-8', 'replace'))
