import math


def _key_order(key):
    # numeric order of key letters (stable)
    enumerated = list(enumerate(key))
    sorted_key = sorted(enumerate(key), key=lambda x: (x[1], x[0]))
    order = {}
    for rank, (idx, _) in enumerate(sorted_key):
        order[idx] = rank
    # return list where position -> order
    return [order[i] for i in range(len(key))]


def transposition_encrypt(plaintext, key):
    text = ''.join([c for c in plaintext if c.isalpha()]).upper()
    if not text:
        return ''
    cols = len(key)
    rows = math.ceil(len(text) / cols)
    # fill grid row-wise
    grid = [['' for _ in range(cols)] for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(cols):
            if idx < len(text):
                grid[r][c] = text[idx]
                idx += 1
            else:
                grid[r][c] = 'X'
    order = _key_order(key)
    # read columns in order
    result = []
    for ord_val in range(cols):
        col_idx = order.index(ord_val)
        for r in range(rows):
            result.append(grid[r][col_idx])
    return ''.join(result)


def transposition_decrypt(ciphertext, key):
    text = ''.join([c for c in ciphertext if c.isalpha()]).upper()
    if not text:
        return ''
    cols = len(key)
    rows = math.ceil(len(text) / cols)
    order = _key_order(key)
    # build empty grid
    grid = [['' for _ in range(cols)] for _ in range(rows)]
    idx = 0
    for ord_val in range(cols):
        col_idx = order.index(ord_val)
        for r in range(rows):
            grid[r][col_idx] = text[idx]
            idx += 1
    # read row-wise
    result = []
    for r in range(rows):
        for c in range(cols):
            result.append(grid[r][c])
    return ''.join(result).rstrip('X')
