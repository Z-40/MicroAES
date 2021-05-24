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
    def split_blocks(blocks: bytes) -> list:
        """Split a byte string into 16-byte blocks"""
        return [blocks[x:x + 16] for x in range(0, len(blocks), 16)]

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

    def __init__(self, master_key: bytes) -> None:
        """AES class for encrypting and decrypting
        Available Modes:
            ECB (Electronic Codebook)

        NOTE: Will be adding CBC, CTR, OFB and CFB modes soon!
            
        :param master_key: 128, 192 or 256 bit long byte string
        :returnType: NoneType
        :return: None
        :raises: BadKeyLength when key entered is not of correct lenght,
            i.e, 128, 192 or 156 bits
        """
        key_variants = {16: 10, 24: 12, 32: 14}
        if len(master_key) not in key_variants:
            raise BadKeyLength(
                "Key of length {} is not supported".format(len(master_key))
            )

        self.master_key = master_key
        self.rounds = key_variants[len(self.master_key)]
        self.round_keys = self.expand_key()
        self.state = []

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

    def expand_key(self) -> None:
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

    def encrypt_ecb(self, plain_text: bytes) -> bytes:
        """Encrypt using ECB (Electronic Codebook) mode"""
        plain_text = self.add_padding(plain_text)
        blocks = self.split_blocks(plain_text)

        return b"".join([self.encrypt_block(block) for block in blocks])

    def decrypt_ecb(self, cipher_text: bytes) -> bytes:
        """Decrypt using ECB (Electronic Codebook) mode
        `cipher_text` must be created using ECB mode using AES"""
        blocks = self.split_blocks(cipher_text)
        decrypted = b"".join([self.decrypt_block(block) for block in blocks])

        return self.remove_padding(decrypted)


if __name__ == "__main__":
    pass
