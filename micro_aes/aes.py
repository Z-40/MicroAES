from constants import TABLE2
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


def to_grid(text, length):
    grid = []
    for index in range(0, length, 4):
        grid.append(list(text[index:index+4]))

    return grid


def from_grid(grid):
    return bytes(sum(grid, []))


def substitute(grid):
    for x in range(4):
        for y in range(4):
            grid[x][y] = SUBSTITUTION_BOX[grid[x][y]]

    return grid


def substitute_inverse(grid):
    for x in range(4):
        for y in range(4):
            grid[x][y] = INVERSE_SUBSTITUTION_BOX[grid[x][y]]

    return grid


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


def mix_columns_inverse(grid):
    for x in grid:
        inverse_mix_single_column(x)


def mix_columns(grid):
    for x in grid:
        mix_single_column(x) 


def shift_rows(grid):
    # shift 2nd row
    grid[1][0], grid[1][1], grid[1][2], grid[1][3] = \
        grid[1][1], grid[1][2], grid[1][3], grid[1][0]

    # shift 3rd row
    grid[2][0], grid[2][1], grid[2][2], grid[2][3] = \
        grid[2][2], grid[2][3], grid[2][0], grid[2][1]

    # shift 4th row
    grid[3][0], grid[3][1], grid[3][2], grid[3][3] = \
        grid[3][3], grid[3][0], grid[3][1], grid[3][2]

    return grid


def shift_rows_inverse(grid):
    # shift 2nd row
    grid[1][1], grid[1][2], grid[1][3], grid[1][0] = \
        grid[1][0], grid[1][1], grid[1][2], grid[1][3]

    # shift 3rd row
    grid[2][2], grid[2][3], grid[2][0], grid[2][1] = \
        grid[2][0], grid[2][1], grid[2][2], grid[2][3]

    # shift 4th row
    grid[3][3], grid[3][0], grid[3][1], grid[3][2] = \
        grid[3][0], grid[3][1], grid[3][2], grid[3][3]

    return grid


def xor_round(x, r): 
        x[0] ^= ROUND_CONSTANT[r]
        return x
        

def xor_word(a, b): 
    return [y ^ b[x] for x, y in enumerate(a)]


def rotate_word(x): 
    x.append(x.pop(0))


def substitute_word(x): 
    return [SUBSTITUTION_BOX[y] for y in x]


def expand_key(master_key, rounds):
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

    return [from_grid(key) for key in keys]

m = expand_key(to_grid(b"1234567890123456", 16), 10)

for x in m:
    print(x)
    print(len(x))
