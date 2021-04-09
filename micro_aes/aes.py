import doctest
from constants import SUBSTITUTION_BOX
from constants import INVERSE_SUBSTITUTION_BOX


def xor_bytes(a, b):
    """
    xor 2 byte strings 
    >>> xor_bytes(b"abc", b"xyz")
    b'\x19\x1b\x19'
    """
    return bytes([x ^ y for x, y in zip(a, b)])


def to_grid(text):
    """ 
    Convert ``text`` into a 4x4 grid, ``text`` must be 16 characters long
    >>> to_grid(b"abcdefghijklmnop")
    [[97, 98, 99, 100], [101, 102, 103, 104], [105, 106, 107, 108], [109, 110, 111, 112]]
    """
    # make sure that the length of ``text`` is 16 bytes
    assert len(text) == 16

    grid = []
    for index in range(0, 16, 4):
        grid.append(list(text[index:index+4]))

    return grid


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
    (2, 3, 1, 1)
    (1, 2, 3, 1)
    (1, 1, 2, 3)
    (3, 1, 1, 2)
    """
    column[0] = (column[0] * 2) ^ (column[1] * 3) ^ (column[2] * 1) ^ (column[3] * 1)
    column[1] = (column[0] * 1) ^ (column[1] * 2) ^ (column[2] * 3) ^ (column[3] * 1)
    column[2] = (column[0] * 1) ^ (column[1] * 1) ^ (column[2] * 2) ^ (column[3] * 3)
    column[3] = (column[0] * 2) ^ (column[1] * 1) ^ (column[2] * 1) ^ (column[3] * 2)

    return [x for x in column]


def mix_columns(grid):
    """ Mix all columns in the ``grid`` """
    return [mix_single_column(x) for x in grid] 


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


if __name__ == "__main__":
    doctest.testmod(verbose=True)

