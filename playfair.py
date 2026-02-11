import string


def _prepare_key(key):
    # Build 5x5 table for Playfair (combine I/J)
    key = ''.join([c.upper() for c in key if c.isalpha()])
    key = key.replace('J', 'I')
    seen = []
    for c in key:
        if c not in seen:
            seen.append(c)
    for c in string.ascii_uppercase:
        if c == 'J':
            continue
        if c not in seen:
            seen.append(c)
    table = [seen[i * 5:(i + 1) * 5] for i in range(5)]
    return table


def _locate(table, ch):
    ch = 'I' if ch == 'J' else ch
    for r in range(5):
        for c in range(5):
            if table[r][c] == ch:
                return r, c
    return None


def _prepare_text(text):
    text = ''.join([c.upper() for c in text if c.isalpha()])
    text = text.replace('J', 'I')
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = ''
        if i + 1 < len(text):
            b = text[i + 1]
        if b == '' or a == b:
            pairs.append((a, 'X'))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    if len(pairs[-1]) == 1:
        pairs[-1] = (pairs[-1][0], 'X')
    return pairs


def playfair_encrypt(plaintext, key):
    table = _prepare_key(key)
    # prepare pairs
    text = ''.join([c for c in plaintext if c.isalpha()])
    pairs = []
    i = 0
    text = text.upper().replace('J', 'I')
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else 'X'
        if a == b:
            pairs.append((a, 'X'))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    if len(pairs[-1]) == 1:
        pairs[-1] = (pairs[-1][0], 'X')
    cipher = []
    for a, b in pairs:
        ra, ca = _locate(table, a)
        rb, cb = _locate(table, b)
        if ra == rb:
            cipher.append(table[ra][(ca + 1) % 5])
            cipher.append(table[rb][(cb + 1) % 5])
        elif ca == cb:
            cipher.append(table[(ra + 1) % 5][ca])
            cipher.append(table[(rb + 1) % 5][cb])
        else:
            cipher.append(table[ra][cb])
            cipher.append(table[rb][ca])
    return ''.join(cipher)


def playfair_decrypt(ciphertext, key):
    table = _prepare_key(key)
    text = [c for c in ciphertext.upper() if c.isalpha()]
    pairs = [(text[i], text[i + 1]) for i in range(0, len(text), 2)]
    plain = []
    for a, b in pairs:
        ra, ca = _locate(table, a)
        rb, cb = _locate(table, b)
        if ra == rb:
            plain.append(table[ra][(ca - 1) % 5])
            plain.append(table[rb][(cb - 1) % 5])
        elif ca == cb:
            plain.append(table[(ra - 1) % 5][ca])
            plain.append(table[(rb - 1) % 5][cb])
        else:
            plain.append(table[ra][cb])
            plain.append(table[rb][ca])
    return ''.join(plain)
