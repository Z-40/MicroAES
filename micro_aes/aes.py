from constants import TABLE2
from constants import TABLE3
from constants import TABLE9
from constants import TABLE11
from constants import TABLE13
from constants import TABLE14
from constants import ROUND_CONSTANT
from constants import SUBSTITUTION_BOX
from constants import INVERSE_SUBSTITUTION_BOX


def xor_bytes(a, b):
    """xor 2 byte strings"""
    return bytes([x ^ y for x, y in zip(a, b)])


def to_grid(text, length):
    """Convert ``text`` into a 4x4 grid"""
    grid = []
    for index in range(0, length, 4):
        grid.append(list(text[index:index+4]))

    return grid


def from_grid(grid):
    """Convert ``grid`` into a string of 16 characters"""
    return bytes(sum(grid, []))


def substitute(grid):
    """Substitute each byte of the ``grid`` using the s-box"""
    for x in range(4):
        for y in range(4):
            grid[x][y] = SUBSTITUTION_BOX[grid[x][y]]

    return grid


def substitute_inverse(grid):
    """Get the original bytes of the ``grid`` using inverse s-box"""
    for x in range(4):
        for y in range(4):
            grid[x][y] = INVERSE_SUBSTITUTION_BOX[grid[x][y]]

    return grid


def mix_single_column(column):
    column[0] = TABLE2[column[0]] ^ TABLE3[column[1]] ^ column[2] ^ column[3]
    column[1] = column[0] ^ TABLE2[column[1]] ^ TABLE3[column[2]] ^ column[3]
    column[2] = column[0] ^ column[1] ^ TABLE2[column[2]] ^ TABLE3[column[3]]
    column[3] = TABLE3[column[0]] ^ column[1] ^ column[2] ^ TABLE2[column[3]]


def inverse_mix_single_column(column):
    column[0] = TABLE14[column[0]] ^ TABLE11[column[1]] ^ \
        TABLE13[column[2]] ^ TABLE9[column[3]]
    column[1] = TABLE9[column[0]] ^ TABLE14[column[1]] ^ \
        TABLE11[column[2]] ^ TABLE13[column[3]]
    column[2] = TABLE13[column[0]] ^ TABLE9[column[1]] ^ \
        TABLE14[column[2]] ^ TABLE11[column[3]]
    column[3] = TABLE11[column[0]] ^ TABLE13[column[1]] ^ \
        TABLE9[column[2]] ^ TABLE14[column[3]]


def mix_columns_inverse(grid):
    """Mix all columns in the ``grid``"""
    for x in grid:
        inverse_mix_single_column(x)


def mix_columns(grid):
    """Mix all columns in the ``grid``"""
    for x in grid:
        mix_single_column(x) 


def shift_rows(grid):
    """ Shift rows of the ``grid`` """
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
    """ Reverse the shift rows step """
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


def expand_key(master_key, rounds):
    def xor_round(x, r): 
        x[0] ^= ROUND_CONSTANT[r]
        return x
        
    def xor_word(a, b): 
        return [y ^ b[x] for x, y in enumerate(a)]

    def rotate_word(x): 
        x.append(x.pop(0))

    def substitute_word(x): 
        return [SUBSTITUTION_BOX[y] for y in x]

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
