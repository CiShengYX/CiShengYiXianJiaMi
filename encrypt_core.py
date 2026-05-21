"""
加密核心模块 - B站-此生已陷-内容加密
AES-256-GCM 加密，数据追加到 PNG IEND 之后
"""

import hashlib
import os
import struct

MAGIC = b'\x43\x53\x59\x58\x5f\x45\x4e\x43'  # CSYX_ENC
VERSION = 1

CONTENT_IMAGE = 0x01
CONTENT_VIDEO = 0x02
CONTENT_TEXT  = 0x03
CONTENT_AUDIO = 0x04
CONTENT_FILE  = 0x05

PBKDF2_ITERATIONS = 100000
_KEY_CACHE: dict = {}


def _derive_key(password, salt):
    cache_key = (password, salt)
    if cache_key in _KEY_CACHE:
        return _KEY_CACHE[cache_key]
    if len(_KEY_CACHE) > 256:
        _KEY_CACHE.clear()
    pwd = password.encode('utf-8') if password else b'CSYX_DEFAULT_KEY'
    key = hashlib.pbkdf2_hmac('sha256', pwd, salt, PBKDF2_ITERATIONS, dklen=32)
    _KEY_CACHE[cache_key] = key
    return key


def _get_cover_png():
    cover_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cover.png")
    with open(cover_path, "rb") as f:
        return f.read()


# Cache cover PNG bytes at module load time
_COVER_BYTES = None
_COVER_CLEAN = None


def _get_clean_cover_png():
    global _COVER_BYTES, _COVER_CLEAN
    if _COVER_CLEAN is None:
        _COVER_BYTES = _get_cover_png()
        _COVER_CLEAN = _strip_png_metadata(_COVER_BYTES)
    return _COVER_CLEAN


def _strip_png_metadata(png_data):
    signature = png_data[:8]
    if signature != b'\x89PNG\r\n\x1a\n':
        raise ValueError("Not a valid PNG")

    keep = {b'IHDR', b'PLTE', b'IDAT', b'IEND', b'tRNS', b'cHRM',
            b'gAMA', b'iCCP', b'sBIT', b'sRGB', b'bKGD', b'hIST',
            b'pHYs', b'sPLT', b'acTL', b'fcTL', b'fdAT'}

    result = bytearray(signature)
    pos = 8
    while pos < len(png_data):
        if pos + 8 > len(png_data):
            break
        length = struct.unpack(">I", png_data[pos:pos+4])[0]
        chunk_type = png_data[pos+4:pos+8]
        chunk_end = pos + 12 + length
        if chunk_end > len(png_data):
            break
        if chunk_type in keep:
            result.extend(png_data[pos:chunk_end])
        pos = chunk_end
        if chunk_type == b'IEND':
            break
    return bytes(result)


def encrypt_data(raw_data, content_type, password="", original_filename=""):
    aes_encrypt = _get_aes_encrypt_func()

    has_password = 1 if password else 0
    salt = os.urandom(16)
    iv = os.urandom(12)

    key = _derive_key(password, salt)

    ciphertext, tag = aes_encrypt(key, iv, raw_data)

    filename_bytes = original_filename.encode('utf-8') if original_filename else b''

    packet = bytearray()
    packet.extend(MAGIC)
    packet.append(VERSION)
    packet.append(content_type)
    packet.append(has_password)
    packet.extend(salt)
    packet.extend(iv)
    packet.extend(tag)
    packet.extend(struct.pack(">H", len(filename_bytes)))
    packet.extend(filename_bytes)
    packet.extend(struct.pack(">Q", len(ciphertext)))
    packet.extend(ciphertext)

    clean_cover = _get_clean_cover_png()
    return clean_cover + bytes(packet)


def _get_aes_encrypt_func():
    try:
        from Crypto.Cipher import AES as _AES
        def encrypt(key, iv, data):
            cipher = _AES.new(key, _AES.MODE_GCM, nonce=iv)
            ct, tag = cipher.encrypt_and_digest(data)
            return ct, tag
        return encrypt
    except ImportError:
        pass

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
        def encrypt(key, iv, data):
            aesgcm = _AESGCM(key)
            ct_tag = aesgcm.encrypt(iv, data, None)
            return ct_tag[:-16], ct_tag[-16:]
        return encrypt
    except ImportError:
        pass

    # 无加速库警告 — 仅首次触发
    if not getattr(_get_aes_encrypt_func, '_warned', False):
        print("[CSYX 警告] 未检测到 pycryptodome 或 cryptography 库，"
              "将使用纯 Python AES 加密（速度极慢）。"
              "建议执行: pip install pycryptodome")
        _get_aes_encrypt_func._warned = True
    return _pure_python_aes_gcm_encrypt


# ============================================================
# Pure Python AES-256-GCM (no dependencies)
# ============================================================

_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
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
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


class _AESCipher:
    def __init__(self, key):
        assert len(key) in (16, 24, 32)
        self._Nk = len(key) // 4
        self._Nr = self._Nk + 6
        self._w = self._expand(key)

    def _expand(self, key):
        Nk, Nr = self._Nk, self._Nr
        w = []
        for i in range(Nk):
            w.append([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])
        for i in range(Nk, 4*(Nr+1)):
            t = list(w[i-1])
            if i % Nk == 0:
                t = [_SBOX[t[1]], _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
                t[0] ^= _RCON[i//Nk - 1]
            elif Nk > 6 and i % Nk == 4:
                t = [_SBOX[b] for b in t]
            w.append([a ^ b for a, b in zip(w[i-Nk], t)])
        return w

    def encrypt_block(self, block):
        assert len(block) == 16
        w, Nr = self._w, self._Nr

        # Load state column-major: s[row][col] = block[row + 4*col]
        s = [[block[r + 4*c] for c in range(4)] for r in range(4)]

        # Round 0: AddRoundKey
        for c in range(4):
            for r in range(4):
                s[r][c] ^= w[c][r]

        for rnd in range(1, Nr):
            # SubBytes
            for r in range(4):
                for c in range(4):
                    s[r][c] = _SBOX[s[r][c]]
            # ShiftRows
            s[1] = [s[1][1], s[1][2], s[1][3], s[1][0]]
            s[2] = [s[2][2], s[2][3], s[2][0], s[2][1]]
            s[3] = [s[3][3], s[3][0], s[3][1], s[3][2]]
            # MixColumns
            for c in range(4):
                a0, a1, a2, a3 = s[0][c], s[1][c], s[2][c], s[3][c]
                s[0][c], s[1][c], s[2][c], s[3][c] = _mc(a0, a1, a2, a3)
            # AddRoundKey
            for c in range(4):
                wrd = w[rnd*4 + c]
                for r in range(4):
                    s[r][c] ^= wrd[r]

        # Final round (no MixColumns)
        for r in range(4):
            for c in range(4):
                s[r][c] = _SBOX[s[r][c]]
        s[1] = [s[1][1], s[1][2], s[1][3], s[1][0]]
        s[2] = [s[2][2], s[2][3], s[2][0], s[2][1]]
        s[3] = [s[3][3], s[3][0], s[3][1], s[3][2]]
        for c in range(4):
            wrd = w[Nr*4 + c]
            for r in range(4):
                s[r][c] ^= wrd[r]

        out = bytearray(16)
        for c in range(4):
            for r in range(4):
                out[r + 4*c] = s[r][c]
        return bytes(out)


def _mc(a0, a1, a2, a3):
    def xt(v):
        return ((v << 1) ^ 0x1b) & 0xff if v & 0x80 else (v << 1) & 0xff
    return (
        xt(a0) ^ xt(a1) ^ a1 ^ a2 ^ a3,
        a0 ^ xt(a1) ^ xt(a2) ^ a2 ^ a3,
        a0 ^ a1 ^ xt(a2) ^ xt(a3) ^ a3,
        xt(a0) ^ a0 ^ a1 ^ a2 ^ xt(a3),
    )


def _inc32(block):
    b = bytearray(block)
    c = int.from_bytes(b[12:16], 'big')
    c = (c + 1) & 0xFFFFFFFF
    b[12:16] = c.to_bytes(4, 'big')
    return bytes(b)


def _gcm_ctr(aes, J0, data):
    result = bytearray()
    counter = _inc32(J0)
    i = 0
    while i < len(data):
        block = aes.encrypt_block(counter)
        chunk = data[i:i+16]
        for j in range(len(chunk)):
            result.append(chunk[j] ^ block[j])
        counter = _inc32(counter)
        i += 16
    return bytes(result)


def _gf128_mult(x, y):
    R = 0xe1000000000000000000000000000000
    xi = int.from_bytes(x, 'big')
    yi = int.from_bytes(y, 'big')
    z = 0
    for i in range(128):
        if (yi >> (127 - i)) & 1:
            z ^= xi
        if xi & 1:
            xi = (xi >> 1) ^ R
        else:
            xi >>= 1
    return z.to_bytes(16, 'big')


def _ghash(H, A, C):
    def pad16(d):
        r = len(d) % 16
        return d + b'\x00' * (16 - r) if r else d

    data = pad16(A) + pad16(C)
    data += struct.pack(">QQ", len(A) * 8, len(C) * 8)

    y = b'\x00' * 16
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        xored = bytes(a ^ b for a, b in zip(y, block))
        y = _gf128_mult(H, xored)
    return y


def _pure_python_aes_gcm_encrypt(key, iv, plaintext):
    aes = _AESCipher(key)
    H = aes.encrypt_block(b'\x00' * 16)

    if len(iv) == 12:
        J0 = iv + b'\x00\x00\x00\x01'
    else:
        J0 = _ghash(H, b'', iv)

    ciphertext = _gcm_ctr(aes, J0, plaintext)
    S = _ghash(H, b'', ciphertext)
    ej0 = aes.encrypt_block(J0)
    tag = bytes(a ^ b for a, b in zip(S, ej0))

    return ciphertext, tag
