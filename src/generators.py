# generators.py
import struct

class LinearCongruentialGenerator:
    """
    LCG implementation using Numerical Recipes parameters:
    X_{n+1} = (a * X_n + c) % m
    """
    def __init__(self, seed: int = 1234567890):
        self.m = 2**32
        self.a = 1664525
        self.c = 1013904223
        self.state = seed & 0xFFFFFFFF

    def next_bits(self) -> bytes:
        """Advances state and returns the raw 32-bit integer packed as 4 bytes."""
        self.state = (self.a * self.state + self.c) % self.m
        return struct.pack('>I', self.state)


class ChaCha20PRNG:
    """
    ChaCha20-based CSPRNG implementation conforming to RFC 8439.
    Uses an internal 4x4 state matrix of 32-bit words.
    """
    def __init__(self, key_bytes: bytes, nonce_bytes: bytes = b'\x00'*12):
        if len(key_bytes) != 32:
            raise ValueError("ChaCha20 key (seed) must be exactly 32 bytes.")
        if len(nonce_bytes) != 12:
            raise ValueError("ChaCha20 nonce must be exactly 12 bytes.")
            
        self.key = struct.unpack('<8I', key_bytes)
        self.nonce = struct.unpack('<3I', nonce_bytes)
        self.counter = 1  # 32-bit block counter per RFC 8439

    @staticmethod
    def _rotate_left(v: int, c: int) -> int:
        """Performs 32-bit bitwise left rotation."""
        return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))

    def _quarter_round(self, x: list, a: int, b: int, c: int, d: int):
        """Executes the standard ARX Quarter-Round engine modification."""
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = self._rotate_left(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = self._rotate_left(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = self._rotate_left(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = self._rotate_left(x[b] ^ x[c], 7)

    def generate_block(self) -> bytes:
        """Runs 20 rounds over matrix and returns a 64-byte raw keystream block."""
        # Constants setup: "expand 32-byte k"
        constants = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
        
        # Correctly maps exactly 16 words: 4 (const) + 8 (key) + 1 (counter) + 3 (nonce)
        state = (
            list(constants) + 
            list(self.key) + 
            [self.counter & 0xFFFFFFFF] + 
            list(self.nonce)
        )
        working_state = list(state)

        # Execute 20 rounds (10 column rounds + 10 diagonal rounds)
        for _ in range(10):
            # Column Rounds
            self._quarter_round(working_state, 0, 4, 8, 12)
            self._quarter_round(working_state, 1, 5, 9, 13)
            self._quarter_round(working_state, 2, 6, 10, 14)
            self._quarter_round(working_state, 3, 7, 11, 15)
            # Diagonal Rounds
            self._quarter_round(working_state, 0, 5, 10, 15)
            self._quarter_round(working_state, 1, 6, 11, 12)
            self._quarter_round(working_state, 2, 7, 8, 13)
            self._quarter_round(working_state, 3, 4, 9, 14)

        # Core matrix step: Add working state back to initial state matrix
        for i in range(16):
            working_state[i] = (working_state[i] + state[i]) & 0xFFFFFFFF

        # Increment 32-bit block counter
        self.counter = (self.counter + 1) & 0xFFFFFFFF

        # Pack the 16 32-bit words into exactly 64 little-endian bytes
        return struct.pack('<16I', *working_state)