# Copyright (C) 2021 Z-40

"""Allows the user to encrypt/decrypt using AES (Advanced Encryption Standard) with
CBC, CTR, CFB and OFB modes of encryption and HMAC for authentication"""

import os
import hmac
import hashlib

from typing import List
# from typing import Union
# from typing import Generator

from micro_aes.constants import GF02
from micro_aes.constants import GF03
from micro_aes.constants import GF09
from micro_aes.constants import GF11
from micro_aes.constants import GF13
from micro_aes.constants import GF14
from micro_aes.constants import ROUND_CONSTANT
from micro_aes.constants import SUBSTITUTION_BOX
from micro_aes.constants import INVERSE_SUBSTITUTION_BOX

# Supported hashes and their digest sizes
HASHES = {
    "md5": 16,
    "sha1": 20,
    "sha224": 28,
    "sha256": 32,
    "sha384": 48,
    "sha512": 64,
}

# Buffer for reading files, this is as high as I could make it
# before causing an OverFlowError
BUFFER = 999999999


def available_hashes():
    """Return a list of all supported hashes"""
    return [h for h in HASHES.keys()]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings"""
    return bytes([x ^ y for x, y in zip(a, b)])


def xor_round(word, r):
    """XOR the first byte of a word with the round constant"""
    word[0] ^= ROUND_CONSTANT[r]
    return word


def increment_bytes(text: bytes) -> bytes:
    """Increment a byte string by one"""
    return int.to_bytes(
        int.from_bytes(bytes=text, byteorder="big") + 1,
        length=len(text),
        byteorder="big"
    )


def calculate_data(password: bytes, salt: bytes, aes_key_size: int):
    """Create an AES key, hmac key and iv using SCRYPT"""
    derived_key = hashlib.scrypt(
        dklen=aes_key_size + 32,
        password=password,
        salt=salt,
        n=16384,
        r=8,
        p=1
    )
    aes_key, derived_key = derived_key[:aes_key_size], derived_key[aes_key_size:]
    hmac_key, derived_key = derived_key[:16], derived_key[16:]
    iv = derived_key[:16]

    return aes_key, hmac_key, iv


def to_matrix(text: bytes) -> List[List[int]]:
    """Convert 16-byte byte string into 4x4 matrix"""
    return [list(text[index:index+4]) for index in range(0, len(text), 4)]


def from_matrix(state: list) -> bytes:
    """Convert 4x4 matrix into 16-byte byte string"""
    return bytes(sum(state, []))


class AES:
    @staticmethod
    def add_padding(plain_text: bytes) -> bytes:
        """Add PKCS#7 padding to a byte string"""
        pad_length = 16 - (len(plain_text) % 16)
        padding = bytes([pad_length] * pad_length)

        return plain_text + padding

    @staticmethod
    def remove_padding(plain_text: bytes) -> bytes:
        """Remove PKCS#7 padding from byte string"""
        return plain_text[:-plain_text[-1]]

    @staticmethod
    def split_blocks(text: bytes) -> list:
        """Split a byte string into 16-byte blocks"""
        return [text[x:x+16] for x in range(0, len(text), 16)]

    @staticmethod
    def mix_single_column(column: list) -> None:
        """Mix a column from AES matrix"""
        c = [b for b in column]
        column[0] = GF02[c[0]] ^ GF03[c[1]] ^ c[2] ^ c[3]
        column[1] = c[0] ^ GF02[c[1]] ^ GF03[c[2]] ^ c[3]
        column[2] = c[0] ^ c[1] ^ GF02[c[2]] ^ GF03[c[3]]
        column[3] = GF03[c[0]] ^ c[1] ^ c[2] ^ GF02[c[3]]

    @staticmethod
    def inverse_mix_single_column(column: list) -> None:
        """Un-Mix a column from AES matrix"""
        c = [b for b in column]
        column[0] = GF14[c[0]] ^ GF11[c[1]] ^ GF13[c[2]] ^ GF09[c[3]]
        column[1] = GF09[c[0]] ^ GF14[c[1]] ^ GF11[c[2]] ^ GF13[c[3]]
        column[2] = GF13[c[0]] ^ GF09[c[1]] ^ GF14[c[2]] ^ GF11[c[3]]
        column[3] = GF11[c[0]] ^ GF13[c[1]] ^ GF09[c[2]] ^ GF14[c[3]]

    __slots__ = ["master_key", "round_keys", "rounds", "state", "hmac", "iv"]

    def __init__(self, master_key: bytes, salt: bytes, strength: int):
        """AES class for encrypting and decrypting
        ### Available Modes:
        - CBC (Cipher Block Chaining)
        - CFB (Cipher FeedBack)
        - CTR (CounTeR)
        - OFB (Output FeedBack)

        ### Attributes:
        - master_key: This will be used to derive the secret key, HMAC key and the IV
            using SCRYPT, a key derivation function. This should be at least 
            least 8 characters long.

        - salt: Salt data for the key derivation function. Should be at least 32 bytes
            in length and must completely random, this can be achieved using 
            `os.urandom()`

        - strength: Desired encryption strength, input 16, 24 or 32 for 128, 192 
            and 256 bits of AES encryption respectively.
        """
        key, hmac_key, iv = calculate_data(master_key, salt, strength)
        
        self.master_key = key
        self.round_keys = self.expand_key()
        self.rounds = {16: 10, 24: 12, 32: 14}[len(self.master_key)]
        self.state = []
        self.hmac = hmac_key
        self.iv = iv

    def substitute(self) -> None:
        """Perform the AES Substitute Byte step"""
        for x in range(4):
            for y in range(4):
                self.state[x][y] = SUBSTITUTION_BOX[self.state[x][y]]

    def substitute_inverse(self) -> None:
        """Reverse AES Substitute Byte step"""
        for x in range(4):
            for y in range(4):
                self.state[x][y] = INVERSE_SUBSTITUTION_BOX[self.state[x][y]]

    def mix_columns(self) -> None:
        """Perform AES Mix Columns step"""
        for x in self.state:
            self.mix_single_column(x)

    def mix_columns_inverse(self) -> None:
        """Reverse AES Mix Columns step"""
        for x in self.state:
            self.inverse_mix_single_column(x)

    def shift_rows(self) -> None:
        """Perform AES Shift Rows step"""
        # shift 2nd row
        self.state[1][0], self.state[1][1], self.state[1][2], self.state[1][3] = \
            self.state[1][1], self.state[1][2], self.state[1][3], self.state[1][0]

        # shift 3rd row
        self.state[2][0], self.state[2][1], self.state[2][2], self.state[2][3] = \
            self.state[2][2], self.state[2][3], self.state[2][0], self.state[2][1]

        # shift 4th row
        self.state[3][0], self.state[3][1], self.state[3][2], self.state[3][3] = \
            self.state[3][3], self.state[3][0], self.state[3][1], self.state[3][2]

    def shift_rows_inverse(self) -> None:
        """Reverse AES Shift Rows step"""
        # shift 2nd row
        self.state[1][1], self.state[1][2], self.state[1][3], self.state[1][0] = \
            self.state[1][0], self.state[1][1], self.state[1][2], self.state[1][3]

        # shift 3rd row
        self.state[2][2], self.state[2][3], self.state[2][0], self.state[2][1] = \
            self.state[2][0], self.state[2][1], self.state[2][2], self.state[2][3]

        # shift 4th row
        self.state[3][3], self.state[3][0], self.state[3][1], self.state[3][2] = \
            self.state[3][0], self.state[3][1], self.state[3][2], self.state[3][3]

    def expand_key(self) -> List[bytes]:
        """Expand 128, 192 or 256 bit keys and return list of round keys
        Number of round keys depend on key size:
        - 128-bit => 11 round keys
        - 192-bit => 13 round keys
        - 256-bit => 15 round keys"""
        xor_word = lambda a, b: [y ^ b[x] for x, y in enumerate(a)]
        rotate_word = lambda word: word.append(word.pop(0))
        substitute_word = lambda word: [SUBSTITUTION_BOX[y] for y in word]

        rounds = {16: 11, 24: 13, 32: 15}[len(self.master_key)]
        words = [word for word in to_matrix(self.master_key)]

        for r in range(1, rounds):
            rotate_word(words[len(words) - 1])
            words.append(
                xor_word(words[-4], xor_round(substitute_word(words[len(words) - 1]), r))
            )

            for _ in range(3):
                words.append(xor_word(words[len(words) - 1], words[-4]))

        keys = []
        for i in range(0, len(words), 4):
            keys.append(list(words[i:i+4]))

        return [from_matrix(k) for k in keys[:-2]]

    def add_round_key(self, key_index: int) -> None:
        """Perform AES Add Round Key step"""
        key_matrix = to_matrix(self.round_keys[key_index])
        for x in range(4):
            for y in range(4):
                self.state[x][y] ^= key_matrix[x][y]

    def _encrypt_block(self, plain_text: bytes) -> bytes:
        """Encrypt 16-byte block using AES"""
        self.state = to_matrix(plain_text)
        self.add_round_key(0)

        for i in range(1, len(self.round_keys) - 1):
            self.substitute()
            self.shift_rows()
            self.mix_columns()
            self.add_round_key(i)

        self.substitute()
        self.shift_rows()
        self.add_round_key(-1)

        return from_matrix(self.state)

    def _decrypt_block(self, cipher_text: bytes) -> bytes:
        """Decrypt 16-byte block using AES"""
        self.state = to_matrix(cipher_text)
        self.add_round_key(-1)
        self.shift_rows_inverse()
        self.substitute_inverse()

        for i in range((len(self.round_keys) - 1) - 1, 0, -1):
            self.add_round_key(i)
            self.mix_columns_inverse()
            self.shift_rows_inverse()
            self.substitute_inverse()

        self.add_round_key(0)

        return from_matrix(self.state)

    def _encrypt_cbc(self, plain_text: bytes) -> bytes:
        """Encrypt using CBC (Cipher Block Chaining) mode"""
        blocks = []
        previous = self.iv
        for block in self.split_blocks(self.add_padding(plain_text)):
            encrypted = self._encrypt_block(xor_bytes(previous, block))
            blocks.append(encrypted)
            previous = encrypted

        return b"".join(blocks)

    def _decrypt_cbc(self, cipher_text: bytes) -> bytes:
        """Decrypt cipher text created using CBC (Cipher Block Chaining) mode"""
        blocks = []
        previous = self.iv
        for block in self.split_blocks(cipher_text):
            blocks.append(xor_bytes(previous, self._decrypt_block(block)))
            previous = block

        return self.remove_padding(b"".join(blocks))

    def _encrypt_ofb(self, plain_text: bytes) -> bytes:
        """Encrypt using OFB (Output FeedBack) mode"""
        new_iv = self._encrypt_block(self.iv)
        blocks = []
        for x in self.split_blocks(plain_text):
            blocks.append(xor_bytes(x, new_iv))
            new_iv = self._encrypt_block(new_iv)

        return b"".join(blocks)

    def _decrypt_ofb(self, cipher_text: bytes) -> bytes:
        """Decrypt cipher text created using OFB (Output FeedBack) mode"""
        new_iv = self._encrypt_block(self.iv)
        blocks = []
        for x in self.split_blocks(cipher_text):
            blocks.append(xor_bytes(x, new_iv))
            new_iv = self._encrypt_block(new_iv)

        return b"".join(blocks)

    def _encrypt_cfb(self, plain_text: bytes) -> bytes:
        """Encrypt using CFB (Cipher FeedBack) mode"""
        blocks = []
        previous = self.iv
        for x in self.split_blocks(plain_text):
            encrypted = xor_bytes(x, self._encrypt_block(previous))
            previous = encrypted
            blocks.append(encrypted)

        return b"".join(blocks)

    def _decrypt_cfb(self, cipher_text: bytes) -> bytes:
        """Decrypt cipher text created using CFB (Cipher FeedBack) mode"""
        blocks = []
        previous = self.iv
        for x in self.split_blocks(cipher_text):
            decrypted = xor_bytes(x, self._encrypt_block(previous))
            previous = decrypted
            blocks.append(decrypted)

        return b"".join(blocks)

    def _encrypt_ctr(self, plain_text: bytes) -> bytes:
        """Encrypt using CTR (CounTeR) mode"""
        blocks = []
        new_iv = self.iv
        for x in self.split_blocks(plain_text):
            encrypted = xor_bytes(x, self._encrypt_block(new_iv))
            blocks.append(encrypted)
            new_iv = increment_bytes(new_iv)

        return b"".join(blocks)

    def _decrypt_ctr(self, cipher_text: bytes) -> bytes:
        """Decrypt cipher text created using CTR (CounTeR) mode"""
        blocks = []
        new_iv = self.iv
        for x in self.split_blocks(cipher_text):
            encrypted = xor_bytes(x, self._encrypt_block(new_iv))
            blocks.append(encrypted)
            new_iv = increment_bytes(new_iv)

        return b"".join(blocks)

    def encrypt(self, plain_text: bytes, mode: str, hasher: str) -> bytes:
        """
        Encrypt `plain_text` using AES and HMAC for authentication

        ### Usage: 

        >>> import micro_aes
        >>> aes_256 = micro_aes.AES(b"p@5sW0rd", b"s4L7&p3pp3r", 32)
        >>> encrypted = aes_256.encrypt(b"HeLlO, wOrLD!", "cbc", "sha256")
        """
        aes_modes = {
            "cbc": self._encrypt_cbc,
            "ctr": self._encrypt_ctr,
            "cfb": self._encrypt_cfb,
            "ofb": self._encrypt_ofb
        }
        assert mode in aes_modes
        assert hasher in HASHES

        # Compute the cipher text and HMAC signature
        text = aes_modes[mode](plain_text)
        sign = hmac.new(self.hmac, plain_text, hasher).digest()

        # The final output is HMAC Signature + Salt + Cipher Text
        return sign + os.urandom(16) + text

    def decrypt(self, cipher_text: bytes, mode: str, hasher: str) -> bytes:
        """
        Decrypt `cipher_text` and authenticate the HMAC signature.

        ### Usage:

        >>> import micro_aes
        >>> aes_256 = micro_aes.AES(b"p@5sW0rd", b"s4L7&p3pp3r", 32)
        >>> encrypted = aes_256.encrypt(b"HeLlO, wOrLD!", "cbc", "sha256")
        >>> decrypted = aes_256.decrypt(encrypted, "cbc", "sha256")
        >>> print(decrypted)
        >>> b"HeLlO, wOrLD!"
        """
        aes_modes = {
            "cbc": self._decrypt_cbc,
            "ctr": self._decrypt_ctr,
            "cfb": self._decrypt_cfb,
            "ofb": self._decrypt_ofb
        }
        assert mode in aes_modes
        assert hasher in HASHES

        # Separate the HMAC signature, salt and cipher text
        digest_size = HASHES[hasher]
        signature, cipher_text = cipher_text[:digest_size], cipher_text[digest_size:]
        salt = cipher_text[:16]
        cipher_text = cipher_text.strip(salt)

        # Decrypt the cipher text
        text = aes_modes[mode](cipher_text)

        # Authenticate the message
        expected_mac = hmac.new(self.hmac, text, hasher).digest()
        assert hmac.compare_digest(signature, expected_mac)

        return text

    def encrypt_file(self, in_file: str, mode: str, hasher: str, keep_original=True) -> None:
        """
        Create an encrypted version of a file
        If `keep_original` is set to true, an encrypted version of the file will be 
        created in the same directory as the original file, othervise, the original 
        file will be replaced with the encrypted one.
        """
        with open(in_file, "rb", buffering=BUFFER) as f:
            in_file_data = f.read()

        # Encrypt the file name
        out_file = self.encrypt(bytes(os.path.split(in_file)[1], "UTF-8"), mode, hasher)
        out_file_path = os.path.split(in_file)[0] + "\\" + bytes.hex(out_file)

        # Create the file and write encrypted data
        with open(out_file_path, "wb", buffering=BUFFER) as f:
            f.write(self.encrypt(in_file_data, mode, hasher))
            f.flush()
        
        if not keep_original:
            os.remove(in_file)
            
    def decrypt_file(self, in_file: str, mode: str, hasher: str, keep_original=True) -> None:
        """
        Decrypt a file
        If `keep_original` is set to true, a decrypted version of the file will be 
        created in the same directory as the encrypted file, othervise, the encrypted 
        file will be replaced with the decrypted file
        """
        with open(in_file, "rb", buffering=BUFFER) as f:
            in_file_data = f.read()

        # Decrypt the file name
        out_file = self.decrypt(bytes.fromhex(os.path.split(in_file)[1]), mode, hasher)
        out_file = out_file.decode("UTF-8")
        out_file_path = os.path.split(in_file)[0] + "\\" + out_file
        
        # Decrypt the data and write data to the file
        with open(out_file_path, "wb", buffering=BUFFER) as f:
            f.write(self.decrypt(in_file_data, mode, hasher))
            f.flush()

        if not keep_original:
            os.remove(in_file)


__all__ = [
    "available_hashes",
    "increment_bytes",
    "calculate_data",
    "from_matrix",
    "xor_round",
    "xor_bytes",
    "to_matrix",
    "HASHES",
    "AES"
]
