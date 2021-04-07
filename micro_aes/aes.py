from constants import SUBSTITUTION_BOX, INVERSE_SUBSTITUTION_BOX

def xor_bytes(a, b):
    """ xor 2 byte strings """
    return bytes([x ^ y for x, y in zip(a, b)])


def to_grid(text):
    """ convert ``text`` into a 4x4 grid """
    # make sure that the length of ``text`` is 16 bytes
    assert len(text) == 16

    grid = []
    for index in range(0, 16, 4):
        grid.append(list(text[index:index+4]))

    return grid


def substitute(grid): 
    """ substitute each byte of the ``grid`` using the s-box"""
    for x in range(4):
        for y in range(4):
            grid[x][y] = SUBSTITUTION_BOX[grid[x][y]]

    return grid

def substitute_inverse(grid):
    """ get the original bytes of the ``grid`` using inverse s-box"""
    for x in range(4):
        for y in range(4):
            grid[x][y] = INVERSE_SUBSTITUTION_BOX[grid[x][y]]

    return grid
