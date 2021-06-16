import os
import hmac
import base64
import hashlib

from micro_aes.constants import GF02
from micro_aes.constants import GF03
from micro_aes.constants import GF09
from micro_aes.constants import GF11
from micro_aes.constants import GF13
from micro_aes.constants import GF14
from micro_aes.constants import ROUND_CONSTANT
from micro_aes.constants import SUBSTITUTION_BOX
from micro_aes.constants import INVERSE_SUBSTITUTION_BOX


HASHES = {
    "md5": hashlib.md5().digest_size,
    "sha1": hashlib.sha1().digest_size,
    "sha224": hashlib.sha224().digest_size,
    "sha256": hashlib.sha256().digest_size,
    "sha384": hashlib.sha384().digest_size,
    "sha512": hashlib.sha512().digest_size,
}


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings"""
    return bytes([x ^ y for x, y in zip(a, b)])


def increment_bytes(text: bytes) -> bytes:
    return int.to_bytes(
        int.from_bytes(bytes=text, byteorder="big") + 1,
        length=len(text),
        byteorder="big"
    )


def calculate_data(password, salt, prf, aes_key_size, iterations=100000):
    """Create an AES key, hmac key and iv"""
    derived_key = hashlib.pbkdf2_hmac(prf, password, salt, iterations, aes_key_size + 32)
    aes_key, derived_key = derived_key[:aes_key_size], derived_key[aes_key_size:]
    hmac_key, derived_key = derived_key[:16], derived_key[16:]
    iv = derived_key[:16]

    return aes_key, hmac_key, iv


def to_matrix(text: bytes) -> list:
    """Convert 16-byte byte string into 4x4 matrix"""
    return [list(text[index:index+4]) for index in range(0, len(text), 4)]


def from_matrix(state: list) -> bytes:
    """Convert 4x4 matrix into 16-byte byte string"""
    return bytes(sum(state, []))


class BadKeyLength(BaseException):
    """Raised when the length of the key is not 128, 192, 256 bits"""


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
        """Mix a given column from AES matrix"""
        c = [b for b in column]
        column[0] = GF02[c[0]] ^ GF03[c[1]] ^ c[2] ^ c[3]
        column[1] = c[0] ^ GF02[c[1]] ^ GF03[c[2]] ^ c[3]
        column[2] = c[0] ^ c[1] ^ GF02[c[2]] ^ GF03[c[3]]
        column[3] = GF03[c[0]] ^ c[1] ^ c[2] ^ GF02[c[3]]

    @staticmethod
    def inverse_mix_single_column(column: list) -> None:
        """Un-Mix a given column from AES matrix"""
        c = [b for b in column]
        column[0] = GF14[c[0]] ^ GF11[c[1]] ^ GF13[c[2]] ^ GF09[c[3]]
        column[1] = GF09[c[0]] ^ GF14[c[1]] ^ GF11[c[2]] ^ GF13[c[3]]
        column[2] = GF13[c[0]] ^ GF09[c[1]] ^ GF14[c[2]] ^ GF11[c[3]]
        column[3] = GF11[c[0]] ^ GF13[c[1]] ^ GF09[c[2]] ^ GF14[c[3]]

    def __init__(self, master_key: bytes, salt: bytes, strength: int, prf="sha256") -> None:
        """AES class for encrypting and decrypting
        Available Modes:
            CBC (Cipher Block Chaining)
            CFB (Cipher FeedBack)
            CTR (CounTeR)
            OFB (Output FeedBack)
        """
        key_variants = {16: 10, 24: 12, 32: 14}
        key, hmac, iv = calculate_data(master_key, salt, prf, strength)
        
        self.master_key = key
        self.round_keys = self.expand_key()
        self.rounds = key_variants[len(self.master_key)]
        self.state = []
        self.hmac = hmac
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

    def expand_key(self) -> bytes:
        """Expand 128, 192 or 256 bit keys and return list of round keys
        Number of round keys depend on key size:
            128-bit => 11 round keys
            192-bit => 13 round keys
            256-bit => 15 round keys"""
        def xor_round(word, round_number):
            word[0] ^= ROUND_CONSTANT[round_number]
            return word

        def xor_word(a, b):
            return [y ^ b[x] for x, y in enumerate(a)]

        def rotate_word(word):
            word.append(word.pop(0))

        def substitute_word(word):
            return [SUBSTITUTION_BOX[y] for y in word]

        key_rounds = {16: 10, 24: 12, 32: 14}
        rounds = key_rounds[len(self.master_key)]
        words = [word for word in to_matrix(self.master_key)]

        for r in range(1, rounds + 2):
            rotate_word(words[len(words) - 1])
            words.append(
                xor_word(words[-4], xor_round(substitute_word(words[len(words) - 1]), r))
            )

            for _ in range(3):
                words.append(xor_word(words[len(words) - 1], words[-4]))

        keys = []
        for index in range(0, len(words), 4):
            keys.append(list(words[index:index + 4]))

        return [from_matrix(k) for k in keys[:-2]]

    def add_round_key(self, key_index: int) -> None:
        """Perform AES Add Round Key step"""
        key_matrix = to_matrix(self.round_keys[key_index])
        for x in range(4):
            for y in range(4):
                self.state[x][y] ^= key_matrix[x][y]

    def encrypt_block(self, plain_text: bytes) -> bytes:
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

    def decrypt_block(self, cipher_text: bytes) -> bytes:
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
            encrypted = self.encrypt_block(xor_bytes(previous, block))
            blocks.append(encrypted)
            previous = encrypted

        return b"".join(blocks)

    def _decrypt_cbc(self, cipher_text: bytes) -> bytes:
        """Decrypt cipher text created using CBC (Cipher Block Chaining) mode"""
        blocks = []
        previous = self.iv
        for block in self.split_blocks(cipher_text):
            blocks.append(xor_bytes(previous, self.decrypt_block(block)))
            previous = block

        return self.remove_padding(b"".join(blocks))

    def _encrypt_ofb(self, plain_text: bytes) -> bytes:
        """Encrypt using OFB (Output FeedBack) mode"""
        new_iv = self.encrypt_block(self.iv)
        blocks = []
        for x in self.split_blocks(plain_text):
            blocks.append(xor_bytes(x, new_iv))
            new_iv = self.encrypt_block(new_iv)

        return b"".join(blocks)

    def _decrypt_ofb(self, cipher_text: bytes) -> bytes:
        """Decrypt cipher text created using OFB (Output FeedBack) mode"""
        new_iv = self.encrypt_block(self.iv)
        blocks = []
        for x in self.split_blocks(cipher_text):
            blocks.append(xor_bytes(x, new_iv))
            new_iv = self.encrypt_block(new_iv)

        return b"".join(blocks)

    def _encrypt_cfb(self, plain_text: bytes) -> bytes:
        """Encrypt using CFB (Cipher FeedBack) mode"""
        blocks = []
        previous = self.iv
        for x in self.split_blocks(plain_text):
            encrypted = xor_bytes(x, self.encrypt_block(previous))
            previous = encrypted
            blocks.append(encrypted)

        return b"".join(blocks)

    def _decrypt_cfb(self, cipher_text: bytes) -> bytes:
        """Decrypt cipher text created using CFB (Cipher FeedBack) mode"""
        blocks = []
        previous = self.iv
        for x in self.split_blocks(cipher_text):
            decrypted = xor_bytes(x, self.encrypt_block(previous))
            previous = decrypted
            blocks.append(decrypted)

        return b"".join(blocks)

    def _encrypt_ctr(self, plain_text: bytes) -> bytes:
        """Encrypt using CTR (CounTeR) mode"""
        blocks = []
        new_iv = self.iv
        for x in self.split_blocks(plain_text):
            encrypted = xor_bytes(x, self.encrypt_block(new_iv))
            blocks.append(encrypted)
            new_iv = increment_bytes(new_iv)

        return b"".join(blocks)

    def _decrypt_ctr(self, cipher_text: bytes) -> bytes:
        """Decrypt cipher text created using CTR (CounTeR) mode"""
        blocks = []
        new_iv = self.iv
        for x in self.split_blocks(cipher_text):
            encrypted = xor_bytes(x, self.encrypt_block(new_iv))
            blocks.append(encrypted)
            new_iv = increment_bytes(new_iv)

        return b"".join(blocks)

    def encrypt(self, plain_text: bytes, mode: str, hasher: str) -> bytes:
        """Encrypt `plain_text` using specified AES `mode`"""
        aes_modes = {
            "cbc": self._encrypt_cbc,
            "ctr": self._encrypt_ctr,
            "cfb": self._encrypt_cfb,
            "ofb": self._encrypt_ofb
        }
        assert mode in aes_modes
        assert hasher in HASHES

        cipher_text = aes_modes[mode](plain_text)
        mac = hmac.new(self.hmac, plain_text, hasher).digest()

        return mac + os.urandom(16) + cipher_text


    def decrypt(self, cipher_text: bytes, mode: str, hasher: str) -> bytes:
        """Decrypt `cipher_text` created using specified AES `mode`"""
        aes_modes = {
            "cbc": self._decrypt_cbc,
            "ctr": self._decrypt_ctr,
            "cfb": self._decrypt_cfb,
            "ofb": self._decrypt_ofb
        }
        assert mode in aes_modes
        assert hasher in HASHES

        digest_size = HASHES[hasher]

        mac, cipher_text = cipher_text[:digest_size], cipher_text[digest_size:]
        salt = cipher_text[:16]
        cipher_text = cipher_text.strip(salt)
        plain_text = aes_modes[mode](cipher_text)

        expected_mac = hmac.new(self.hmac, plain_text, hasher).digest()

        assert hmac.compare_digest(mac, expected_mac)
        return plain_text

    def encrypt_file(self, in_file: str, out_file: str, mode: str, hasher: str) -> None:
        with open(in_file, "rb") as f:
            in_file_data = f.read()

        encrypted = base64.encodebytes(self.encrypt(in_file_data, mode, hasher))
        with open(out_file, "wb") as f:
            f.write(encrypted)

    def decrypt_file(self, in_file: str, out_file: str, mode: str, hasher: str) -> None:
        with open(in_file, "rb") as f:
            in_file_data = f.read()

        decrypted = self.decrypt(base64.decodebytes(in_file_data), mode, hasher)
        with open(out_file, "wb") as f:
            f.write(decrypted)


__all__ = ["AES"]
