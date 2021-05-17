from constants import GF02
from constants import GF03
from constants import GF09
from constants import GF11
from constants import GF13
from constants import GF14
from constants import ROUND_CONSTANT
from constants import SUBSTITUTION_BOX
from constants import INVERSE_SUBSTITUTION_BOX


def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


def to_matrix(text):
    return [list(text[index:index+4]) for index in range(0, len(text), 4)]


def from_matrix(state):
    return bytes(sum(state, []))


def substitute(state):
    for x in range(4):
        for y in range(4):
            state[x][y] = SUBSTITUTION_BOX[state[x][y]]

    return state


def substitute_inverse(state):
    for x in range(4):
        for y in range(4):
            state[x][y] = INVERSE_SUBSTITUTION_BOX[state[x][y]]

    return state


def mix_single_column(column):
    c = [b for b in column]
    column[0] = GF02[c[0]] ^ GF03[c[1]] ^ c[2] ^ c[3]
    column[1] = c[0] ^ GF02[c[1]] ^ GF03[c[2]] ^ c[3]
    column[2] = c[0] ^ c[1] ^ GF02[c[2]] ^ GF03[c[3]]
    column[3] = GF03[c[0]] ^ c[1] ^ c[2] ^ GF02[c[3]]


def inverse_mix_single_column(column):
    c = [b for b in column]
    column[0] = GF14[c[0]] ^ GF11[c[1]] ^ GF13[c[2]] ^ GF09[c[3]]
    column[1] = GF09[c[0]] ^ GF14[c[1]] ^ GF11[c[2]] ^ GF13[c[3]]
    column[2] = GF13[c[0]] ^ GF09[c[1]] ^ GF14[c[2]] ^ GF11[c[3]]
    column[3] = GF11[c[0]] ^ GF13[c[1]] ^ GF09[c[2]] ^ GF14[c[3]]


def mix_columns_inverse(state):
    for x in state:
        inverse_mix_single_column(x)


def mix_columns(state):
    for x in state:
        mix_single_column(x)


def shift_rows(state):
    # shift 2nd row
    state[1][0], state[1][1], state[1][2], state[1][3] = \
        state[1][1], state[1][2], state[1][3], state[1][0]

    # shift 3rd row
    state[2][0], state[2][1], state[2][2], state[2][3] = \
        state[2][2], state[2][3], state[2][0], state[2][1]

    # shift 4th row
    state[3][0], state[3][1], state[3][2], state[3][3] = \
        state[3][3], state[3][0], state[3][1], state[3][2]

    return state


def shift_rows_inverse(state):
    # shift 2nd row
    state[1][1], state[1][2], state[1][3], state[1][0] = \
        state[1][0], state[1][1], state[1][2], state[1][3]

    # shift 3rd row
    state[2][2], state[2][3], state[2][0], state[2][1] = \
        state[2][0], state[2][1], state[2][2], state[2][3]

    # shift 4th row
    state[3][3], state[3][0], state[3][1], state[3][2] = \
        state[3][0], state[3][1], state[3][2], state[3][3]

    return state


def xor_round(word, round):
    word[0] ^= ROUND_CONSTANT[round]
    return word


def xor_word(a, b):
    return [y ^ b[x] for x, y in enumerate(a)]


def rotate_word(word):
    word.append(word.pop(0))


def substitute_word(word):
    return [SUBSTITUTION_BOX[y] for y in word]


def expand_key(master_key, rounds):
    master_key = to_matrix(master_key)
    rounds += 1

    words = [word for word in master_key]
    for r in range(1, rounds + 1):
        rotate_word(words[len(words) - 1])
        words.append(
            xor_word(words[-4], xor_round(substitute_word(words[len(words) - 1]), r))
        )

        for _ in range(3):
            words.append(xor_word(words[len(words) - 1], words[-4]))

    keys = []
    for index in range(0, len(words), 4):
        keys.append(list(words[index:index+4]))

    return [from_matrix(k) for k in keys]


def add_round_key(state, key):
    key_matrix = to_matrix(key)
    for x, y in enumerate(state):
        for a, b in enumerate(y):
            state[x][a] = key_matrix[x][a] ^ b


if __name__ == "__main__":
    pass