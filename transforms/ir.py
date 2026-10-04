"""Small unsigned-64 IR. Frontends lower benchmark logic, not arbitrary C/C++."""
from dataclasses import dataclass

MASK = (1 << 64) - 1
OPS = ('const', 'mov', 'add', 'sub', 'mul', 'div', 'mod', 'and', 'or', 'xor',
       'shl', 'shr', 'eq', 'lt', 'le', 'select', 'load', 'store', 'jump', 'branch', 'halt')

@dataclass
class Inst:
    op: str
    d: int = 0
    a: int = 0
    b: int = 0
    c: int = 0
    imm: int = 0

class Program:
    def __init__(self, name):
        self.name, self.code, self.labels, self.fixups = name, [], {}, []
        self.next_reg = 16  # 0..7 input, 8..15 output
        self.constants = {}

    def reg(self):
        r = self.next_reg; self.next_reg += 1
        return r

    def emit(self, op, d=0, a=0, b=0, c=0, imm=0):
        self.code.append(Inst(op, d, a, b, c, imm)); return d

    def const(self, value):
        r = self.reg(); self.emit('const', r, imm=value & MASK); return r

    def calc(self, op, a, b=0, c=0):
        return self.emit(op, self.reg(), a, b, c)

    def copy(self, dest, src): self.emit('mov', dest, src)
    def label(self, name): self.labels[name] = len(self.code)
    def jump(self, name):
        self.fixups.append((len(self.code), name)); self.emit('jump')
    def branch(self, pred, name):
        self.fixups.append((len(self.code), name)); self.emit('branch', a=pred)
    def finish(self):
        self.emit('halt')
        for i, name in self.fixups: self.code[i].imm = self.labels[name]
        if self.next_reg > 256: raise ValueError('Too many registers')
        return self

def pricing():
    p = Program('pricing'); k = p.const
    zero, one, two, hundred = k(0), k(1), k(2), k(100)
    rate = p.calc('select', p.calc('le', k(20), 1), k(12),
                  p.calc('select', p.calc('le', k(7), 1), k(5), zero))
    net = p.calc('mul', 0, 1)
    p.copy(net, p.calc('sub', net, p.calc('div', p.calc('mul', net, rate), hundred)))
    member = p.calc('select', p.calc('eq', 2, one), k(3),
                    p.calc('select', p.calc('eq', 2, two), k(8), zero))
    p.copy(net, p.calc('sub', net, p.calc('div', p.calc('mul', net, member), hundred)))
    eligible = p.calc('and', p.calc('eq', 3, one), p.calc('le', k(2500), net))
    p.copy(net, p.calc('select', eligible, p.calc('sub', net, k(375)), net))
    eligible = p.calc('and', p.calc('eq', 3, two), p.calc('le', k(3), 1))
    eligible = p.calc('and', eligible, p.calc('eq', p.calc('eq', 2, two), zero))
    discounted = p.calc('sub', net, p.calc('div', p.calc('mul', net, k(7)), hundred))
    p.copy(net, p.calc('select', eligible, discounted, net))
    ship = p.calc('select', p.calc('le', k(5000), net), zero, p.calc('add', k(199), p.calc('mul', hundred, 4)))
    taxrate = p.calc('select', p.calc('eq', 4, zero), zero,
                     p.calc('select', p.calc('eq', 4, one), k(650), k(825)))
    tax = p.calc('div', p.calc('add', p.calc('mul', net, taxrate), k(9999)), k(10000))
    total = p.calc('add', p.calc('add', net, ship), tax)
    for dest, src in zip(range(8, 12), (net, ship, tax, total)):
        p.copy(dest, p.calc('select', p.calc('eq', 1, zero), zero, src))
    return p.finish()

def record():
    # memory: input [0,255), output [256,520); input regs kind, seq, flags, length
    p = Program('record'); k = p.const
    zero, one, two, ff, base = k(0), k(1), k(2), k(255), k(256)
    def put(offset, value): p.emit('store', a=p.calc('add', base, k(offset)), b=value)
    put(0, k(182)); put(1, p.calc('or', k(64), 0)); put(2, 2)
    put(3, p.calc('and', 1, ff)); put(4, p.calc('shr', 1, k(8))); put(5, 3)
    i = p.reg(); p.copy(i, zero)
    p.label('payload'); p.branch(p.calc('eq', i, 3), 'checksum_start')
    idx = p.calc('select', p.calc('and', 2, one), p.calc('sub', p.calc('sub', 3, one), i), i)
    value = p.calc('load', idx)
    mask = p.calc('and', p.calc('add', p.calc('add', 1, p.calc('mul', k(17), i)), 0), ff)
    value = p.calc('select', p.calc('and', 2, two), p.calc('xor', value, mask), value)
    p.emit('store', a=p.calc('add', p.calc('add', base, k(6)), i), b=value)
    p.copy(i, p.calc('add', i, one)); p.jump('payload')
    p.label('checksum_start'); check = p.reg(); p.copy(check, k(7439)); p.copy(i, zero)
    length = p.calc('add', 3, k(6))
    p.label('checksum'); p.branch(p.calc('eq', i, length), 'done')
    rotated = p.calc('and', p.calc('or', p.calc('shl', check, k(5)), p.calc('shr', check, k(11))), k(65535))
    p.copy(check, p.calc('xor', rotated, p.calc('load', p.calc('add', base, i))))
    p.copy(i, p.calc('add', i, one)); p.jump('checksum')
    p.label('done')
    p.emit('store', a=p.calc('add', base, length), b=p.calc('shr', check, k(8)))
    p.emit('store', a=p.calc('add', p.calc('add', base, length), one), b=p.calc('and', check, ff))
    p.copy(8, p.calc('add', length, two))
    return p.finish()

def session():
    # Scalar transition kernel. Host keeps map/iteration and forwards all decisions here.
    # in: op, quantity, amount, deadline, available, sold, clock, delta
    # out: status (0 OK,1 DUP,2 SHORT,3 MISSING), available,sold,clock,amount,deadline,expired
    p = Program('session'); k = p.const
    zero, one = k(0), k(1)
    p.copy(8, zero)
    for dest, src in ((9,4),(10,5),(11,6),(12,2),(13,3)): p.copy(dest, src)
    p.copy(14, zero)
    for op, label in ((1,'hold'),(2,'buy'),(3,'cancel'),(4,'tick'),(5,'expire')):
        p.branch(p.calc('eq', 0, k(op)), label)
    p.jump('end')
    p.label('hold')
    p.branch(p.calc('eq', 2, zero), 'new')
    p.copy(8, one); p.jump('end')
    p.label('new'); p.branch(p.calc('lt', 4, 1), 'short')
    p.copy(9, p.calc('sub', 4, 1)); p.copy(12, 1); p.copy(13, p.calc('add', 6, k(4))); p.jump('end')
    p.label('short'); p.copy(8, k(2)); p.jump('end')
    p.label('buy'); p.branch(p.calc('eq', 2, zero), 'missing')
    p.copy(10, p.calc('add', 5, 2)); p.copy(12, zero); p.copy(13, zero); p.jump('end')
    p.label('cancel'); p.branch(p.calc('eq', 2, zero), 'missing')
    p.copy(9, p.calc('add', 4, 2)); p.copy(12, zero); p.copy(13, zero); p.jump('end')
    p.label('missing'); p.copy(8, k(3)); p.jump('end')
    p.label('tick'); p.copy(11, p.calc('add', 6, 7)); p.jump('end')
    p.label('expire'); p.branch(p.calc('eq', 2, zero), 'end')
    p.branch(p.calc('lt', 6, 3), 'end')
    p.copy(9, p.calc('add', 4, 2)); p.copy(12, zero); p.copy(13, zero); p.copy(14, one)
    p.label('end'); return p.finish()

def auxiliary(index):
    """Independent input-dependent checksum kernel; output checked in audit builds."""
    p = Program(f'auxiliary_{index}'); k = p.const
    acc = p.reg(); p.copy(acc, k(0x9e3779b9 + index))
    for i in range(8):
        mixed = p.calc('add', i, k((index + 1) * (i + 17)))
        p.copy(acc, p.calc('xor', p.calc('mul', acc, k(33 + 2*index)), mixed))
    p.copy(8, acc); return p.finish()

def aux_expected(inputs, index):
    acc = 0x9e3779b9 + index
    for i in range(8): acc = ((acc * (33 + 2*index)) & MASK) ^ ((inputs[i] + (index+1)*(i+17)) & MASK)
    return acc

def interpret(program, inputs, memory=None):
    r = [0] * 256; r[:len(inputs)] = inputs
    mem = list(memory) if memory is not None else [0] * 1024
    pc = 0
    for _ in range(100000):
        ins = program.code[pc]; pc += 1
        op, d = ins.op, ins.d; a,b,c = (r[x] for x in (ins.a, ins.b, ins.c))
        if op == 'halt': return r, mem
        if op == 'jump': pc = ins.imm; continue
        if op == 'branch': pc = ins.imm if a else pc; continue
        if op == 'store': mem[a] = b; continue
        if op == 'const': value = ins.imm
        elif op == 'mov': value = a
        elif op == 'add': value = a+b
        elif op == 'sub': value = a-b
        elif op == 'mul': value = a*b
        elif op == 'div': value = a//b if b else 0
        elif op == 'mod': value = a%b if b else 0
        elif op == 'and': value = a&b
        elif op == 'or': value = a|b
        elif op == 'xor': value = a^b
        elif op == 'shl': value = a << (b&63)
        elif op == 'shr': value = a >> (b&63)
        elif op == 'eq': value = int(a==b)
        elif op == 'lt': value = int(a<b)
        elif op == 'le': value = int(a<=b)
        elif op == 'select': value = b if a else c
        elif op == 'load': value = mem[a]
        else: raise ValueError(op)
        r[d] = value & MASK
    raise RuntimeError('IR instruction limit')

FRONTENDS = {'pricing': pricing, 'record': record, 'session': session}
