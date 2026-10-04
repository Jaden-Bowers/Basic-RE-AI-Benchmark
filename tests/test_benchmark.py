import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import bench


class BenchmarkTests(unittest.TestCase):
    def test_reference_submissions_and_missing_submissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            oracle = (ROOT / 'private/oracle.py').read_text()
            for name in bench.NAMES:
                folder = tmp / 'submission' / name
                folder.mkdir(parents=True)
                (folder / 'solution.py').write_text(oracle + '\nimport sys\nprint("\\n".join(expected(' + repr(name) + ', sys.stdin.read().splitlines())))\n')
                (folder / 'answers.json').write_text(json.dumps(bench.ANSWERS[name]))
            for folder, score in ((tmp / 'submission', 1.0), (tmp / 'missing', 0.0)):
                report = tmp / 'report.json'
                subprocess.run([sys.executable, str(ROOT / 'bench.py'), 'grade', '--submission', str(folder),
                    '--bundle', str(ROOT / 'challenges/baseline'), '--out', str(report)], check=True, capture_output=True)
                result = json.loads(report.read_text())
                self.assertEqual(result['mean_reconstruction'], score)
                self.assertEqual(result['mean_semantic_accuracy'], score)

    def test_execution_failure_and_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(bench.run([sys.executable, '-c', 'raise SystemExit(3)'], ['x'], 2, tmp)[1], 'exit:3')
            self.assertEqual(bench.run([sys.executable, '-c', 'while True: pass'], ['x'], 0.2, tmp)[1], 'timeout')

    def test_mutants_are_detected(self):
        # Concrete alternative semantics that must be distinguished by tests.
        original = (ROOT / 'private/oracle.py').read_text()
        mutants = {
            'pricing': ('q >= 20', 'q > 20'),
            'record': ("s.to_bytes(2, 'little')", "s.to_bytes(2, 'big')"),
            'session': ('end <= now', 'end < now'),
        }
        for name, (before, after) in mutants.items():
            namespace = {}
            exec(original.replace(before, after), namespace)
            self.assertTrue(any(bench.expected(name, lines) != namespace['expected'](name, lines)
                                for _, lines in bench.cases(name, 20261003)), name)

    def test_seed_reproducibility(self):
        for name in bench.NAMES:
            self.assertEqual(bench.cases(name, 77), bench.cases(name, 77))
            self.assertNotEqual(bench.cases(name, 77), bench.cases(name, 78))

    def test_paired_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = {'benchmark_version': '1.0', 'seed': 1, 'timeout_per_process_seconds': 5,
                      'oracle_sha256': 'same', 'task_hashes': {}, 'run_label': 'base',
                      'targets': {n: {'reconstruction': 1.0, 'semantic_accuracy': 1.0} for n in bench.NAMES}}
            bench.save(tmp / 'a.json', report)
            report['run_label'] = 'treated'
            report['targets']['pricing']['reconstruction'] = 0.5
            bench.save(tmp / 'b.json', report)
            args = argparse.Namespace(baseline=tmp / 'a.json', treatment=tmp / 'b.json', out=tmp / 'diff.json')
            bench.compare(args)
            self.assertEqual(json.loads(args.out.read_text())['targets']['pricing']['reconstruction_drop_pp'], 50)
            report['seed'] = 2
            bench.save(tmp / 'b.json', report)
            with self.assertRaises(RuntimeError): bench.compare(args)


if __name__ == '__main__': unittest.main()
