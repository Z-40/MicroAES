from constants import GF02
from constants import GF03
from constants import GF09
from constants import GF11
from constants import GF13
from constants import GF14
from constants import ROUND_CONSTANT
from constants import SUBSTITUTION_BOX
from constants import INVERSE_SUBSTITUTION_BOX


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings"""
    return bytes([x ^ y for x, y in zip(a, b)])

def increment_bytes(text: bytes) -> bytes:
    return int.to_bytes(
        int.from_bytes(bytes=text, byteorder="big") + 1,
        length=len(text),
        byteorder="big"
    )

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

    def __init__(self, master_key: bytes, iv: bytes) -> None:
        """AES class for encrypting and decrypting
        Available Modes:
            ECB (Electronic Codebook)

        NOTE: Will be adding CBC, CTR, OFB and CFB modes soon!

        :param master_key: 128, 192 or 256 bit long byte string
        :returnType: NoneType
        :return: None
        :raises: BadKeyLength when key entered is not of correct length,
            i.e, 128, 192 or 156 bits
        """
        key_variants = {16: 10, 24: 12, 32: 14}
        if len(master_key) not in key_variants:
            raise BadKeyLength(
                "Key of length {} is not supported".format(len(master_key))
            )

        # make sure the initialization vector is of the correct length
        assert len(iv) == 16

        self.master_key = master_key
        self.round_keys = self.expand_key()
        self.rounds = key_variants[len(self.master_key)]
        self.state = []
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

    def encrypt_cbc(self, plain_text: bytes) -> bytes:
        """Encrypt using CBC (Cipher Block Chaining) mode"""
        blocks = []
        previous = self.iv
        for block in self.split_blocks(self.add_padding(plain_text)):
            encrypted = self.encrypt_block(xor_bytes(previous, block))
            blocks.append(encrypted)
            previous = encrypted

        return b"".join(blocks)

    def decrypt_cbc(self, cipher_text: bytes) -> bytes:
        """Decrypt cipher text created using CBC (Cipher Block Chaining) mode"""
        blocks = []
        previous = self.iv
        for block in self.split_blocks(cipher_text):
            blocks.append(xor_bytes(previous, self.decrypt_block(block)))
            previous = block

        return self.remove_padding(b"".join(blocks))

    def encrypt_ofb(self, plain_text: bytes) -> bytes:
        """Encrypt using OFB (Output FeedBack) mode"""
        new_iv = self.encrypt_block(self.iv)
        blocks = []
        for x in self.split_blocks(plain_text):
            blocks.append(xor_bytes(x, new_iv))
            new_iv = self.encrypt_block(new_iv)

        return b"".join(blocks)

    def decrypt_ofb(self, cipher_text: bytes) -> bytes:
        """Decrypt cipher text created using OFB (Output FeedBack) mode"""
        new_iv = self.encrypt_block(self.iv)
        blocks = []
        for x in self.split_blocks(cipher_text):
            blocks.append(xor_bytes(x, new_iv))
            new_iv = self.encrypt_block(new_iv)

        return b"".join(blocks)

    def encrypt_cfb(self, plain_text: bytes) -> bytes:
        """Encrypt using CFB (Cipher FeedBack) mode"""
        blocks = []
        previous = self.iv
        for x in self.split_blocks(plain_text):
            encrypted = xor_bytes(x, self.encrypt_block(previous))
            previous = encrypted
            blocks.append(encrypted)

        return b"".join(blocks)

    def decrypt_cfb(self, cipher_text: bytes) -> bytes:
        """Decrypt cipher text created using CFB (Cipher FeedBack) mode"""
        blocks = []
        previous = self.iv
        for x in self.split_blocks(cipher_text):
            decrypted = xor_bytes(x, self.encrypt_block(previous))
            previous = decrypted
            blocks.append(decrypted)

        return b"".join(blocks)

    def encrypt_ctr(self, plain_text: bytes) -> bytes:
        """Encrypt using CTR (CounTeR) mode"""
        blocks = []
        new_iv = self.iv
        for x in self.split_blocks(plain_text):
            encrypted = xor_bytes(x, self.encrypt_block(new_iv))
            blocks.append(encrypted)
            new_iv = increment_bytes(new_iv)

        return b"".join(blocks)

    def decrypt_ctr(self, cipher_text: bytes) -> bytes:
        """Decrypt cipher text created using CTR (CounTeR) mode"""
        blocks = []
        new_iv = self.iv
        for x in self.split_blocks(cipher_text):
            encrypted = xor_bytes(x, self.encrypt_block(new_iv))
            blocks.append(encrypted)
            new_iv = increment_bytes(new_iv)

        return b"".join(blocks)

    def encrypt(self, plain_text: bytes, mode: str) -> bytes:
        """Encrypt `plain_text` using specified AES `mode`"""
        aes_modes = {
            "cbc": self.encrypt_cbc,
            "ctr": self.encrypt_ctr,
            "cfb": self.encrypt_cfb,
            "ofb": self.encrypt_ofb
        }
        assert mode in aes_modes
        return aes_modes[mode](plain_text)

    def decrypt(self, cipher_text: bytes, mode: str) -> bytes:
        """Decrypt `cipher_text` created using specified AES `mode`"""
        aes_modes = {
            "cbc": self.decrypt_cbc,
            "ctr": self.decrypt_ctr,
            "cfb": self.decrypt_cfb,
            "ofb": self.decrypt_ofb
        }
        assert mode in aes_modes
        return aes_modes[mode](cipher_text)
