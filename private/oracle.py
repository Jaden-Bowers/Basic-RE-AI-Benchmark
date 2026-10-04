"""Private, independent behavioral references and reproducible test generation."""
import random

def pricing(line):
    try:
        u, q, m, c, r = map(int, line.split())
    except ValueError:
        return 'ERR'
    if not (0 <= u <= 100000 and 0 <= q <= 200 and 0 <= m <= 2 and 0 <= c <= 2 and 0 <= r <= 2):
        return 'ERR'
    if q == 0:
        return '0 0 0 0'
    value = u*q
    value -= value * (12 if q >= 20 else 5 if q >= 7 else 0) // 100
    value -= value * (0, 3, 8)[m] // 100
    if c == 1 and value >= 2500:
        value -= 375
    elif c == 2 and q >= 3 and m != 2:
        value -= value * 7 // 100
    shipping = 0 if value >= 5000 else 199 + 100*r
    tax = -(-(value * (0, 650, 825)[r]) // 10000)
    return f'{value} {shipping} {tax} {value + shipping + tax}'

def record(line):
    try:
        k, s, f, text = line.split()
        k, s, f = int(k), int(s), int(f)
        if not (0 <= k <= 15 and 0 <= s <= 65535 and 0 <= f <= 3):
            return 'ERR'
        if text != '-' and (len(text) % 2 or any(c not in '0123456789abcdefABCDEF' for c in text)):
            return 'ERR'
        data = b'' if text == '-' else bytes.fromhex(text)
        if len(data) > 255:
            return 'ERR'
    except ValueError:
        return 'ERR'
    data = data[::-1] if f & 1 else data
    if f & 2:
        data = bytes(x ^ ((s + 17*i + k) % 256) for i, x in enumerate(data))
    result = bytes([182, 64+k, f]) + s.to_bytes(2, 'little') + bytes([len(data)]) + data
    check = 7439
    for x in result:
        check = ((check * 32 + check // 2048) % 65536) ^ x
    return (result + check.to_bytes(2, 'big')).hex()

def session(lines):
    stock, sold, now, holds = 30, 0, 0, {}
    outputs = []
    for line in lines:
        a = line.split(); op = a[0] if a else ''; result = 'ERR'
        try:
            if op == 'RESET' and len(a) == 1:
                stock, sold, now, holds = 30, 0, 0, {}; result = 'OK'
            elif op == 'STATUS' and len(a) == 1:
                result = f'{stock} {sum(h[0] for h in holds.values())} {sold} {now}'
            elif op == 'HOLD' and len(a) == 3:
                key, count = map(int, a[1:])
                if 1 <= key <= 999 and 1 <= count <= 30:
                    if key in holds: result = 'DUP'
                    elif count > stock: result = 'SHORT'
                    else:
                        stock -= count; holds[key] = (count, now + 4); result = 'OK'
            elif op in ('BUY', 'CANCEL') and len(a) == 2:
                key = int(a[1])
                if 1 <= key <= 999:
                    if key not in holds: result = 'MISSING'
                    else:
                        count, _ = holds.pop(key)
                        if op == 'BUY': sold += count
                        else: stock += count
                        result = 'OK'
            elif op == 'TICK' and len(a) == 2:
                delta = int(a[1])
                if 0 <= delta <= 1000:
                    now += delta
                    expired = [key for key, (_, end) in holds.items() if end <= now]
                    for key in expired: stock += holds.pop(key)[0]
                    result = str(len(expired))
        except ValueError:
            pass
        outputs.append(result)
    return outputs

def expected(name, lines):
    return session(lines) if name == 'session' else [globals()[name](line) for line in lines]

ANSWERS = {
    'pricing': {'bulk_thresholds': [7, 20], 'bulk_percentages': [5, 12], 'member_percentages': [0, 3, 8],
                'coupon1_minimum': 2500, 'coupon1_amount': 375, 'tax_rounding': 'ceil'},
    'record': {'magic': 182, 'sequence_endian': 'little', 'payload_length_offset': 5,
               'checksum_initial': 7439, 'checksum_rotation': 5, 'checksum_endian': 'big'},
    'session': {'initial_stock': 30, 'hold_lifetime': 4, 'expiry_inclusive': True,
                'duplicate_replaces': False, 'buy_returns_stock': False, 'tick_counts': 'holds'},
}

def cases(name, seed):
    """Each item is a category plus a complete fresh-process transcript."""
    rng = random.Random(seed)
    groups = []
    def add(category, lines): groups.append((category, lines))
    if name == 'pricing':
        for _ in range(100):
            add('ordinary', [f'{rng.randrange(100001)} {rng.randrange(201)} {rng.randrange(3)} {rng.randrange(3)} {rng.randrange(3)}'])
        for u in (0, 1, 1249, 1250, 2499, 2500, 4999, 5000, 5001, 100000):
            for q in (0, 1, 2, 3, 6, 7, 19, 20, 200):
                for m in range(3):
                    add('boundaries', [f'{u} {q} {m} {c} {r}' for c in range(3) for r in range(3)])
        for line in ('-1 1 0 0 0', '100001 1 0 0 0', '1 201 0 0 0', '1 1 3 0 0', '1 1 0 3 0', '1 1 0 0 3', '1 1 0', '1 1 0 0 0 9'):
            add('invalid', [line, '100 3 1 2 2'])
    elif name == 'record':
        for _ in range(100):
            n = rng.randrange(1, 100)
            add('ordinary', [f'{rng.randrange(16)} {rng.randrange(65536)} {rng.randrange(4)} {rng.randbytes(n).hex()}'])
        for n in (0, 1, 2, 127, 128, 254, 255):
            for s in (0, 255, 256, 65535):
                add('boundaries', [f'{k} {s} {f} {rng.randbytes(n).hex() if n else "-"}' for k in (0, 15) for f in range(4)])
        for line in ('16 0 0 -', '-1 0 0 -', '0 65536 0 -', '0 0 4 -', '0 0 0 a', '0 0 0 gg', '0 0 0 ' + 'aa'*256, '0 0 0 - extra'):
            add('invalid', [line, '1 256 3 AAbB00'])
    else:
        add('boundaries', ['STATUS', 'HOLD 1 30', 'HOLD 1 1', 'HOLD 2 1', 'TICK 3', 'STATUS', 'TICK 1', 'BUY 1', 'STATUS'])
        add('boundaries', ['HOLD 1 5', 'TICK 2', 'HOLD 2 7', 'TICK 2', 'STATUS', 'BUY 2', 'STATUS', 'RESET', 'STATUS'])
        add('boundaries', ['HOLD 1 8', 'HOLD 2 2', 'TICK 0', 'TICK 4', 'STATUS', 'CANCEL 1'])
        for _ in range(70):
            lines = ['STATUS']
            for _ in range(50):
                op = rng.choice(['HOLD', 'HOLD', 'BUY', 'CANCEL', 'TICK', 'STATUS', 'RESET'])
                if op == 'HOLD': line = f'HOLD {rng.randrange(1, 9)} {rng.randrange(1, 31)}'
                elif op in ('BUY', 'CANCEL'): line = f'{op} {rng.randrange(1, 9)}'
                elif op == 'TICK': line = f'TICK {rng.randrange(6)}'
                else: line = op
                lines.extend([line, 'STATUS'])
            add('sequences', lines)
        for line in ('HOLD 0 1', 'HOLD 1 0', 'HOLD 1000 1', 'HOLD 1 31', 'BUY -1', 'TICK -1', 'TICK 1001', 'RESET extra', 'STATUS extra', 'WHAT', 'HOLD 1'):
            add('invalid', ['HOLD 5 8', line, 'STATUS', 'BUY 5', 'STATUS'])
    return groups
