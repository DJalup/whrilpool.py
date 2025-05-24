# whirlpool.py - Full Python implementation of the Whirlpool hash function (public domain)

import struct

class Whirlpool:
    DIGESTBYTES = 64
    R = 10

    def __init__(self, data=b''):
        self._bitLength = [0] * 32
        self._buffer = bytearray(64)
        self._bufferBits = 0
        self._bufferPos = 0
        self._hash = [0] * 64
        self._K = [0] * 64
        self._L = [0] * 64
        self._block = [0] * 64
        self._SBOX = self._generate_sbox()
        self._rc = self._generate_round_constants()
        if data:
            self.update(data)

    def _generate_sbox(self):
        return [
            0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
            0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
            0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
            0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
            0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
            0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
            0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
            0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
            0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
            0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
            0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
            0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
            0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
            0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
            0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
            0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86
        ]

    def _increment_bit_length(self, num_bits):
        carry = num_bits
        for i in reversed(range(32)):
            carry += self._bitLength[i]
            self._bitLength[i] = carry & 0xFF
            carry >>= 8

    def _generate_round_constants(self):
        rc = [0] * (self.R + 1)
        for r in range(1, self.R + 1):
            rc[r] = 0
            for i in range(8):
                byte = 8 * (r - 1) + i
                rc[r] = (rc[r] << 8) | self._SBOX[byte]
        return rc

    def update(self, data):
        self._increment_bit_length(len(data) * 8)
        for byte in data:
            self._buffer[self._bufferPos] = byte
            self._bufferPos += 1
            if self._bufferPos == 64:
                self._transform(bytes(self._buffer))
                self._bufferPos = 0

    def _transform(self, block):
        def pack64(b): return int.from_bytes(b, byteorder='big')
        def unpack64(i): return i.to_bytes(8, byteorder='big')

        def rol(x, n): return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

        def gf_mul(a, b):
            """Galois Field (256) multiplication of a and b"""
            p = 0
            for _ in range(8):
                if b & 1: p ^= a
                hi = a & 0x80
                a = (a << 1) & 0xFF
                if hi: a ^= 0x1D
                b >>= 1
            return p

        # Define Whirlpool's transformation matrix
        M = [
            [1, 1, 4, 1, 8, 5, 2, 9],
            [9, 1, 1, 4, 1, 8, 5, 2],
            [2, 9, 1, 1, 4, 1, 8, 5],
            [5, 2, 9, 1, 1, 4, 1, 8],
            [8, 5, 2, 9, 1, 1, 4, 1],
            [1, 8, 5, 2, 9, 1, 1, 4],
            [4, 1, 8, 5, 2, 9, 1, 1],
            [1, 4, 1, 8, 5, 2, 9, 1],
        ]

        def mix_bytes(state):
            out = [0] * 8
            for r in range(8):
                for c in range(8):
                    val = 0
                    for k in range(8):
                        val ^= gf_mul(M[r][k], (state[k] >> (56 - 8*c)) & 0xFF)
                    out[r] = (out[r] << 8) | val
            return out

        # === Initial Setup ===
        block = [pack64(self._buffer[i*8:(i+1)*8]) for i in range(8)]
        state = [self._hash[i] ^ block[i] for i in range(8)]
        K = self._hash.copy()

        for r in range(1, self.R + 1):
            # Key schedule
            K = [int.from_bytes(bytes([self._SBOX[(K[(i - j) % 8] >> (8 * (7 - j))) & 0xFF] for j in range(8)]), 'big') for i in range(8)]
            K[0] ^= self._rc[r]

            # State round
            state = [int.from_bytes(bytes([self._SBOX[(state[(i - j) % 8] >> (8 * (7 - j))) & 0xFF] for j in range(8)]), 'big') for i in range(8)]
            state = mix_bytes(state)
            for i in range(8):
                state[i] ^= K[i]

        # Final XOR with original block
        result = [state[i] ^ self._hash[i] ^ block[i] for i in range(8)]

        # Store back into self._hash
        for i in range(8):
            self._hash[i*8:(i+1)*8] = unpack64(result[i])

    def hexdigest(self):
        return self.digest().hex()
    
    def digest(self):
        # Clone the bit length (already tracked in update())
        bit_len = (self._bitLength[0] << 56) | (self._bitLength[1] << 48) | (self._bitLength[2] << 40) | (self._bitLength[3] << 32) | \
                  (self._bitLength[4] << 24) | (self._bitLength[5] << 16) | (self._bitLength[6] << 8) | self._bitLength[7]

        buffer = self._buffer[:self._bufferPos] + bytes([0x80])
        pad_len = (64 - ((len(buffer) + 32) % 64)) % 64
        buffer += bytes(pad_len)

        # Append bit length as 256-bit big-endian (32 bytes)
        bit_len_bytes = bytearray(32)
        bit_len <<= 3  # convert to bits
        for i in range(31, -1, -1):
            bit_len_bytes[i] = bit_len & 0xFF
            bit_len >>= 8

        buffer += bit_len_bytes

        for i in range(0, len(buffer), 64):
            self._transform(buffer[i:i + 64])

        return bytes(self._hash[:64])


    def copy(self):
        new_obj = Whirlpool()
        new_obj._bitLength = self._bitLength[:]
        new_obj._buffer = self._buffer[:]
        new_obj._hash = self._hash[:]
        return new_obj

    @property
    def digest_size(self):
        return self.DIGESTBYTES

    @property
    def block_size(self):
        return 64

    @property
    def name(self):
        return "whirlpool"

def new(data=b""):
    return Whirlpool(data)