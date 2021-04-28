import doctest
from constants import ROUND_CONSTANT
from constants import SUBSTITUTION_BOX
from constants import INVERSE_SUBSTITUTION_BOX


def xor_bytes(a, b):
    """
    xor 2 byte strings

    >>> xor_bytes(b"abc", b"xyz")
    b'\x19\x1b\x19'
    """
    return bytes([x ^ y for x, y in zip(a, b)])


def to_grid(text, length):
    """
    Convert ``text`` into a 4x4 grid

    >>> to_grid(b"abcdefghijklmnop", 16)
    [[97, 98, 99, 100], [101, 102, 103, 104], [105, 106, 107, 108], [109, 110, 111, 112]]
    """
    grid = []
    for index in range(0, length, 4):
        grid.append(list(text[index:index+4]))

    return grid


def from_grid(grid):
    """
    Convert ``grid`` into a string of 16 characters
    """
    return bytes(sum(grid, []))


def substitute(grid):
    """
    Substitute each byte of the ``grid`` using the s-box

    >>> substitute(to_grid(b"abcdefghijklmnop"))
    [[239, 170, 251, 67], [77, 51, 133, 69], [249, 2, 127, 80], [60, 159, 168, 81]]
    """
    for x in range(4):
        for y in range(4):
            grid[x][y] = SUBSTITUTION_BOX[grid[x][y]]

    return grid


def substitute_inverse(grid):
    """
    Get the original bytes of the ``grid`` using inverse s-box

    >>> inv = substitute_inverse(substitute(to_grid(b"abcdefghijklmnop")))
    >>> assert inv == to_grid(b"abcdefghijklmnop")
    """
    for x in range(4):
        for y in range(4):
            grid[x][y] = INVERSE_SUBSTITUTION_BOX[grid[x][y]]

    return grid


def mix_single_column(column):
    """
    Mix a single column of the grid using the multiplication matrix:
    -----------------
    | 2 | 3 | 1 | 1 |
    | 1 | 2 | 3 | 1 |
    | 1 | 1 | 2 | 3 |
    | 3 | 1 | 1 | 2 |
    -----------------

    >>> mix_single_column([1, 3, 5, 7])
    [9, 7, 17, 10]
    """
    column[0] = (column[0] * 0x2) ^ (column[1] * 0x3) ^ (column[2] * 0x1) ^ (column[3] * 0x1)
    column[1] = (column[0] * 0x1) ^ (column[1] * 0x2) ^ (column[2] * 0x3) ^ (column[3] * 0x1)
    column[2] = (column[0] * 0x1) ^ (column[1] * 0x1) ^ (column[2] * 0x2) ^ (column[3] * 0x3)
    column[3] = (column[0] * 0x2) ^ (column[1] * 0x1) ^ (column[2] * 0x1) ^ (column[3] * 0x2)

    return [x for x in column]


def inverse_mix_single_column(column):
    """
    Mix a single column of the grid using the multiplication matrix:
    -----------------
    | 2 | 3 | 1 | 1 |
    | 1 | 2 | 3 | 1 |
    | 1 | 1 | 2 | 3 |
    | 3 | 1 | 1 | 2 |
    -----------------

    >>> mix_single_column([1, 3, 5, 7])
    [9, 7, 17, 10]
    """
    column[0] = (column[0] * 0xe) ^ (column[1] * 0xb) ^ (column[2] * 0xd) ^ (column[3] * 0x9)
    column[1] = (column[0] * 0x9) ^ (column[1] * 0xe) ^ (column[2] * 0xb) ^ (column[3] * 0xd)
    column[2] = (column[0] * 0xd) ^ (column[1] * 0x9) ^ (column[2] * 0xe) ^ (column[3] * 0xb)
    column[3] = (column[0] * 0xb) ^ (column[1] * 0xd) ^ (column[2] * 0x9) ^ (column[3] * 0xe)

    return [x for x in column]


def mix_columns_inverse(grid):
    """
    Mix all columns in the ``grid``

    >>> mix_columns(to_grid(b"abcdefghijklmnop"))
    [[483, 106, 99, 775], [503, 102, 103, 831], [491, 18, 107, 887], [399, 110, 111, 1023]]
    """
    return [inverse_mix_single_column(x) for x in grid]



def mix_columns(grid):
    """
    Mix all columns in the ``grid``

    >>> mix_columns(to_grid(b"abcdefghijklmnop"))
    [[483, 106, 99, 775], [503, 102, 103, 831], [491, 18, 107, 887], [399, 110, 111, 1023]]
    """
    return [mix_single_column(x) for x in grid]


def shift_rows(grid):
    """ Shift rows of the ``grid`` """
    # shift 2nd row
    grid[1][0], grid[1][1], grid[1][2], grid[1][3] = grid[1][1], grid[1][2], grid[1][3], grid[1][0]

    # shift 3rd row
    grid[2][0], grid[2][1], grid[2][2], grid[2][3] = grid[2][2], grid[2][3], grid[2][0], grid[2][1]

    # shift 4th row
    grid[3][0], grid[3][1], grid[3][2], grid[3][3] = grid[3][3], grid[3][0], grid[3][1], grid[3][2]

    return grid


def shift_rows_inverse(grid):
    """ Reverse the shift rows step """
    # shift 2nd row
    grid[1][1], grid[1][2], grid[1][3], grid[1][0] = grid[1][0], grid[1][1], grid[1][2], grid[1][3]

    # shift 3rd row
    grid[2][2], grid[2][3], grid[2][0], grid[2][1] = grid[2][0], grid[2][1], grid[2][2], grid[2][3]

    # shift 4th row
    grid[3][3], grid[3][0], grid[3][1], grid[3][2] = grid[3][0], grid[3][1], grid[3][2], grid[3][3]

    return grid


def expand_key(master_key, rounds):
    # auxillary functions
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
        words.append(xor_word(words[-4], xor_round(substitute_word(words[len(words) - 1]), r)))

        for _ in range(3):
            words.append(xor_word(words[len(words) - 1], words[-4]))

    keys = []
    for index in range(0, len(words), 4):
        keys.append(list(words[index:index+4]))

    return [from_grid(key) for key in keys]


if __name__ == "__main__":
    # doctest.testmod(verbose=True)
    grid = to_grid(b"abcdefghijklmnop", 16)
    print(mix_columns(grid))
    print(mix_columns_inverse(mix_columns(grid)))
