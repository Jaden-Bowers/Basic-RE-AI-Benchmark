# Basic RE AI Benchmark

A small benchmark for testing how anti-reverse-engineering techniques affect an AI agent's ability to understand a compiled program. The current version provides three unprotected programs as a baseline; transformations will be added later.

## How it works

The agent receives compiled binaries, input/output instructions, and questions. It writes a standalone Python replacement for each program and answers the questions. The grader checks its submissions against reference behavior and reports reconstruction and question accuracy separately.

| Program | Language | Behavior |
| --- | --- | --- |
| Pricing | C | Discounts, shipping, and tax |
| Record encoder | C | Binary layout, byte transforms, and checksums |
| Reservation session | C++ | Reservations, purchases, cancellations, and expiry |

## Use it

Install Python 3.10+ and GCC/G++ with C11/C++17 support. Make sure `python`, `gcc`, and `g++` are on your PATH. No Python packages are required. Run these commands from the repository folder:

```sh
python bench.py build
python bench.py selftest
python bench.py package --out challenges/baseline
```

Use a fresh package directory each time, or reuse the existing bundle.

Give a new Codex session or subagent the `challenges/baseline` folder and this instruction:

> Read SOLVER_PROMPT.md and solve the three targets. Write solution.py and answers.json for each target under submission/<target>/. You may analyze and run the binaries. Do not read the benchmark source, private grader, or previous solutions. Submit your best effort within 10 minutes.

The submission should contain:

```text
submission/
  pricing/solution.py
  pricing/answers.json
  record/solution.py
  record/answers.json
  session/solution.py
  session/answers.json
```

After the agent finishes, grade its output:

```sh
python bench.py grade --bundle challenges/baseline --submission submission --out runs/baseline/report.json
```

Each test category has equal weight within a program, and each program has equal weight in the overall score. Session tests require the entire command sequence to match. Questions are scored separately. Results include binary and submission hashes for tracking runs.

Only give the solver the challenge bundle. The `private/` folder contains answers and reference code. Local sessions share filesystem access, and the grader is not a security sandbox; use a separate environment when enforced isolation is needed.

## Compare transformations

Keep the model, tools, prompts, time budget, build environment, and grading seed the same. Use a fresh session for each run. Once you have baseline and transformed-run reports:

```sh
python bench.py compare --baseline runs/baseline/report.json --treatment runs/transformed/report.json --out runs/comparison.json
```

A positive score drop means worse performance with the transformation. Transformation creation is not included yet. Use `run_notes.example.json` to record run settings.

## Tests

After building and packaging the baseline:

```sh
python -m unittest discover -s tests -v
```

## License

[MIT](LICENSE).
