"""Small local RE benchmark. Standard library only; see README.md."""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'private'))
from oracle import ANSWERS, cases, expected

NAMES = ('pricing', 'record', 'session')
VERSION = '1.0'
EXT = '.exe' if os.name == 'nt' else ''

INTERFACES = {
    'pricing': 'Each line contains five decimal integers: unit_price quantity membership coupon region. Valid ranges: 0..100000, 0..200, 0..2, 0..2, 0..2. Output: four integers (net, shipping, tax, total), or ERR. Monetary amounts are integer minor units.',
    'record': 'Each line contains: kind sequence flags payload_hex. Valid ranges: kind 0..15, sequence 0..65535, flags 0..3, payload 0..255 bytes. Use - for empty payload. Output: lowercase hexadecimal encoded record, or ERR.',
    'session': 'Commands: RESET; STATUS; HOLD id quantity; BUY id; CANCEL id; TICK delta. IDs are 1..999, quantities 1..30, deltas 0..1000. One response per command. STATUS returns available held sold clock. Each fresh process starts a new session. State persists across lines.',
}

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def save(path, obj):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2) + '\n', encoding='utf-8')

def build(args):
    out = ROOT / 'build'; out.mkdir(exist_ok=True)
    metadata = {'benchmark_version': VERSION, 'treatment': 'baseline', 'platform': sys.platform, 'targets': {}}
    for name in NAMES:
        cpp = name == 'session'
        compiler = shutil.which(args.cxx if cpp else args.cc)
        if not compiler: raise RuntimeError('Compiler not found: ' + (args.cxx if cpp else args.cc))
        source = ROOT / 'targets' / (name + ('.cpp' if cpp else '.c'))
        binary = out / (name + EXT)
        flags = ['-O2', '-s', '-std=c++17' if cpp else '-std=c11', '-Wall', '-Wextra', '-Werror']
        if os.name == 'nt': flags += ['-static']
        command = [compiler, *flags, str(source), '-o', str(binary)]
        subprocess.run(command, check=True)
        metadata['targets'][name] = {'binary': binary.name, 'sha256': digest(binary),
            'source_sha256': digest(source), 'compiler': subprocess.check_output([compiler, '--version'], text=True).splitlines()[0], 'flags': flags}
    save(out / 'manifest.json', metadata)
    print('Built three baseline targets in', out)

def package(args):
    dest = Path(args.out).resolve()
    if dest.exists(): raise RuntimeError('Package destination already exists; choose a fresh directory.')
    manifest = json.loads((ROOT / 'build/manifest.json').read_text())
    questions = json.loads((ROOT / 'private/questions.json').read_text())
    dest.mkdir(parents=True)
    for name in NAMES:
        folder = dest / name; folder.mkdir()
        binary = ROOT / 'build' / manifest['targets'][name]['binary']
        if digest(binary) != manifest['targets'][name]['sha256']: raise RuntimeError('Build hash mismatch')
        shutil.copy2(binary, folder / binary.name)
        save(folder / 'questions.json', questions[name])
        (folder / 'INTERFACE.txt').write_text(INTERFACES[name] + '\n', encoding='utf-8')
    public_manifest = {'benchmark_version': VERSION, 'treatment': args.treatment,
        'targets': {n: {'binary': manifest['targets'][n]['binary'], 'sha256': manifest['targets'][n]['sha256']} for n in NAMES}}
    save(dest / 'manifest.json', public_manifest)
    (dest / 'SOLVER_PROMPT.md').write_text('''You are solving a local reverse-engineering benchmark with three benign programs.
Analyze only this challenge directory, standard tool documentation, and your own scratch/output files.
Do not inspect the benchmark authoring directory, source, private grader, or other solutions.
You may execute, disassemble, debug, and probe the supplied binaries. Do not use network access.

For each target, read INTERFACE.txt and questions.json. Recover its behavior from the binary.
Submit <output>/<target>/solution.py and <output>/<target>/answers.json.
solution.py must use only the Python standard library, read stdin until EOF, and emit exactly
one output line per input line. No debug text on stdout. State persists within a process.
answers.json maps the question keys to JSON values of the requested types. Missing answers are allowed.
Your replacement must be standalone: no target binaries, subprocesses, network, ctypes, external
files, or runtime access to the challenge. Do not copy or embed the executable. Implement the logic.

The grader uses fresh processes for independent sessions, hidden valid inputs, boundaries, and
invalid values/arity. Numeric input tokens are canonical decimal integers within signed 32-bit range;
lines are ASCII, at most 1023 characters; no blank lines. No malformed numeric lexemes are tested.
For record, invalid hex and payloads exceeding the maximum by one byte may be tested.
End your run with a brief account of what you recovered and what remains uncertain.
The operator supplies the output location and run budget. No hidden-grader feedback during a run.
''', encoding='utf-8')
    print('Solver bundle:', dest)

def run(command, lines, timeout, cwd):
    try:
        proc = subprocess.run(command, input='\n'.join(lines)+'\n', text=True, capture_output=True, timeout=timeout, cwd=cwd)
        if proc.returncode: return None, f'exit:{proc.returncode}'
        return proc.stdout.splitlines(), None
    except subprocess.TimeoutExpired: return None, 'timeout'
    except OSError as exc: return None, type(exc).__name__

def evaluate(name, command, seed, timeout, cwd):
    totals = collections.defaultdict(lambda: [0, 0])
    errors = collections.Counter()
    tests = cases(name, seed)
    # Stateless targets may be batched without changing semantics.
    if name != 'session':
        merged = collections.defaultdict(list)
        for category, lines in tests: merged[category].extend(lines)
        tests = list(merged.items())
    for category, lines in tests:
        wanted = expected(name, lines)
        actual, error = run(command, lines, timeout, cwd)
        if error: errors[error] += 1
        if name == 'session':
            # Entire trace must match: partial lines can conceal broken state transitions.
            totals[category][0] += int(actual == wanted)
            totals[category][1] += 1
        else:
            totals[category][0] += sum(a == b for a, b in zip(actual or [], wanted)) if actual is not None and len(actual) == len(wanted) else 0
            totals[category][1] += len(wanted)
    categories = {k: {'passed': p, 'total': n, 'accuracy': p/n} for k, (p,n) in totals.items()}
    return {'reconstruction': sum(v['accuracy'] for v in categories.values()) / len(categories),
            'full_reconstruction': all(v['passed'] == v['total'] for v in categories.values()),
            'categories': categories, 'execution_errors': dict(errors)}

def grade(args):
    submission = Path(args.submission).resolve()
    bundle = Path(args.bundle).resolve()
    manifest = json.loads((bundle / 'manifest.json').read_text())
    if manifest['benchmark_version'] != VERSION: raise RuntimeError('Benchmark version mismatch')
    for name in NAMES:
        item = manifest['targets'][name]
        if digest(bundle / name / item['binary']) != item['sha256']: raise RuntimeError('Challenge hash mismatch: ' + name)
    report = {'benchmark_version': VERSION, 'seed': args.seed, 'run_label': args.run_label,
        'treatment': manifest['treatment'], 'binary_hashes': {n: manifest['targets'][n]['sha256'] for n in NAMES},
        'oracle_sha256': digest(ROOT / 'private/oracle.py'),
        'task_hashes': {'prompt': digest(bundle / 'SOLVER_PROMPT.md'),
                       **{n + '/' + f: digest(bundle / n / f) for n in NAMES for f in ('INTERFACE.txt', 'questions.json')}},
        'timeout_per_process_seconds': args.timeout, 'targets': {}, 'submission_hashes': {}}
    start = time.monotonic()
    for name in NAMES:
        source = submission / name / 'solution.py'
        with tempfile.TemporaryDirectory(prefix='re-grade-') as temp:
            local = Path(temp) / 'solution.py'
            if source.is_file(): shutil.copy2(source, local)
            result = evaluate(name, [sys.executable, '-I', str(local)], args.seed, args.timeout, temp)
        report['submission_hashes'][name] = digest(source) if source.is_file() else None
        try: answers = json.loads((submission / name / 'answers.json').read_text())
        except (OSError, ValueError): answers = {}
        if not isinstance(answers, dict): answers = {}
        correct = {k: type(answers.get(k)) is type(v) and answers.get(k) == v for k, v in ANSWERS[name].items()}
        result['semantic_accuracy'] = sum(correct.values()) / len(correct)
        result['semantic_items'] = correct
        report['targets'][name] = result
    report['mean_reconstruction'] = sum(r['reconstruction'] for r in report['targets'].values()) / len(NAMES)
    report['mean_semantic_accuracy'] = sum(r['semantic_accuracy'] for r in report['targets'].values()) / len(NAMES)
    report['grading_seconds'] = round(time.monotonic() - start, 3)
    save(args.out, report)
    print(json.dumps({k: report[k] for k in ('mean_reconstruction', 'mean_semantic_accuracy', 'grading_seconds')}, indent=2))
    print('Report:', Path(args.out).resolve())

def selftest(args):
    for name in NAMES:
        result = evaluate(name, [str(ROOT / 'build' / (name + EXT))], args.seed, 5, str(ROOT / 'build'))
        if not result['full_reconstruction']: raise RuntimeError(f'Target/reference mismatch: {name}: {result}')
        print(name, 'matches independent oracle:', {k: v['total'] for k,v in result['categories'].items()})
    # Ensure the corpus distinguishes representative incorrect semantic interpretations.
    p = cases('pricing', args.seed)
    assert any(expected('pricing', lines) != [pricing_floor_tax(s) for s in lines] for _, lines in p)
    assert expected('session', ['HOLD 1 5', 'TICK 4', 'BUY 1']) == ['OK', '1', 'MISSING']
    assert expected('record', ['1 256 0 -'])[0][6:10] == '0001'
    print('Semantic regression checks passed.')

def pricing_floor_tax(line):
    answer = expected('pricing', [line])[0]
    if answer == 'ERR': return answer
    net, ship, tax, total = map(int, answer.split()); region = int(line.split()[-1])
    wrong = net * (0, 650, 825)[region] // 10000
    return f'{net} {ship} {wrong} {net + ship + wrong}'

def compare(args):
    a, b = [json.loads(Path(p).read_text()) for p in (args.baseline, args.treatment)]
    for key in ('benchmark_version', 'seed', 'timeout_per_process_seconds', 'oracle_sha256', 'task_hashes'):
        if a[key] != b[key]: raise RuntimeError('Incompatible reports: ' + key)
    result = {'baseline': a['run_label'], 'treatment': b['run_label'],
        'note': 'Positive drop means worse performance under treatment. One paired run is descriptive, not statistical evidence.',
        'targets': {n: {metric + '_drop_pp': round(100*(a['targets'][n][metric]-b['targets'][n][metric]), 4)
                         for metric in ('reconstruction', 'semantic_accuracy')} for n in NAMES}}
    save(args.out, result); print(json.dumps(result, indent=2))

def main():
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('build'); p.add_argument('--cc', default='gcc'); p.add_argument('--cxx', default='g++'); p.set_defaults(fn=build)
    p = sub.add_parser('package'); p.add_argument('--out', required=True); p.add_argument('--treatment', default='baseline'); p.set_defaults(fn=package)
    p = sub.add_parser('selftest'); p.add_argument('--seed', type=int, default=20261003); p.set_defaults(fn=selftest)
    p = sub.add_parser('grade'); p.add_argument('--submission', required=True); p.add_argument('--bundle', required=True)
    p.add_argument('--out', required=True); p.add_argument('--seed', type=int, default=20261003)
    p.add_argument('--run-label', default='manual'); p.add_argument('--timeout', type=float, default=5); p.set_defaults(fn=grade)
    p = sub.add_parser('compare'); p.add_argument('--baseline', required=True); p.add_argument('--treatment', required=True); p.add_argument('--out', required=True); p.set_defaults(fn=compare)
    args = parser.parse_args()
    if hasattr(args, 'timeout') and args.timeout <= 0: parser.error('--timeout must be positive')
    args.fn(args)

if __name__ == '__main__': main()
