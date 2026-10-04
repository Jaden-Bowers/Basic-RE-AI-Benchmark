# Transformation suite

This branch prepares transformations and their correctness tests. It does not run an AI agent. The implementations are experimental, target-specific transformations of the three benchmark kernels, not a general C/C++ obfuscator or a claim of cryptographic security.

## Variants

| Variant | Implementation |
| --- | --- |
| `plain` | Optimized native code generated from the shared kernel IR, with direct jumps and ordinary storage. This is the matched control. |
| `cfg` | Native operations behind a central program-counter dispatcher. |
| `vm` | Custom register VM with arithmetic, comparison, memory, and control operations. |
| `vm-strong` | VM plus flattened interpreter phases, mixed Boolean/arithmetic substitutions, and masked immediates. |
| `interleave` | Randomized interleaving of the target and independent, input-dependent checksum computations, executed by a native scheduler. |
| `decorrelate` | Interleaving plus predicate-selected control transitions, encoded program counters, per-reference aliases, and changing physical locations and value masks on accesses. |
| `entangle` | Decorrelation plus randomized opcode values/record layout and shared XOR-difference/Fenwick storage spanning multiple streams. |
| `full` | Entangled VM plus packed AES-256-GCM fragments, on-demand loading and cache wiping, with a Windows TPM-backed RSA key unwrapping the AES key. |

`streams` counts the main computation and the auxiliary computations together. The supported strengths are 2, 4, 8, and 16. Auxiliary outputs are consumed through a volatile sink; author-only audit binaries independently check every auxiliary result. The scheduler preserves each computation's order and stops scheduling it when it finishes. It does not pad all streams to equal runtime or equalize opcode distributions.

The existing `python bench.py build` still builds the original C/C++ programs. Keep that baseline as an additional control. The suite's `plain` uses the same lowered kernels and adapters as the protected variants, allowing transformation comparisons without conflating them with lowering changes. Native parsing, formatting, validation, and session map traversal remain outside the protected kernels. The session kernel protects the reservation, purchase, cancellation, clock, and expiry decisions. This is selective protection, not whole-program virtualization.

This is a branching experiment, not a strictly cumulative ladder: `interleave` is native and does not include `vm-strong`. Focus on `vm-strong` versus `decorrelate`, then `decorrelate` versus `entangle`, then `entangle` versus `full`. The latter comparisons still change several mechanisms together; they measure bundles of mechanisms rather than proving which individual component caused a difference.

## Build and validate

Use Python 3.10+, GCC/G++, `nm`, and `strip`. The full stack additionally requires Windows CNG; the other variants can be generated on Windows or Linux. Native validation has been exercised on Windows, not yet on Linux.

For a software-only correctness fixture covering all eight variants:

```sh
python suite.py build --variant all --streams 4 --seeds 1 --key-backend software-test --out build/suite
python suite.py validate --build-dir build/suite/entangle-s4-seed1
python suite.py package --build-dir build/suite/entangle-s4-seed1 --out challenges/entangle
```

Validate each build directory you want to package. Validation runs the reference test corpus against the ordinary binary and a separate audit binary. Packaging requires a current successful validation, checks artifact hashes, and copies only binaries, required runtime assets, interfaces, questions, and public pair tasks. Source, truth maps, compiler manifests, and audit binaries stay in `build/`.

Build directories are immutable to these commands: choose a fresh output root to rebuild. Software-key fixtures are labeled `full-software-test` and ship a plainly accessible `.key` sidecar. They test encryption/loading behavior and **must not be reported as TPM results**. Cryptographic keys/nonces are generated from OS randomness, independently of the structural build seed. Full-stack ciphertext therefore differs on repeated builds even when its structural layout is the same.

To generate five randomized builds:

```sh
python suite.py build --variant entangle --streams 8 --seeds 1 2 3 4 5 --out build/repeats
```

`python suite.py plan --out experiments/plan.json` writes the full preparation matrix: 84 build configurations, each containing three targets (252 binaries). It defines separate fresh-session and transfer-from-seed-1 tracks. It does not compile the matrix or start agents. Structural determinism tests cover every strength and all five seeds; the entire 252-binary matrix is not automatically built by the unit tests.

## Windows TPM setup

The hardware backend uses the Windows **Microsoft Platform Crypto Provider**, a persisted non-exportable RSA key, and RSA-OAEP-SHA256 to unwrap a per-build AES-256 key. It does not set PCR policies, require attestation, or keep plaintext keys in a TEE during execution. Under full observation, the unwrapped key and decrypted operations remain observable.

Provision a dedicated test key explicitly on the machine that will run the challenge:

```powershell
python suite.py keytool
build/tools/keytool.exe provision REBenchmarkTestKey build/tpm-public.blob
python suite.py build --variant full --streams 4 --seeds 1 --tpm-name REBenchmarkTestKey --tpm-public build/tpm-public.blob --out build/tpm-suite
python suite.py validate --build-dir build/tpm-suite/full-s4-seed1
```

Provisioning creates a persistent current-user TPM key and exports only its public blob. It never overwrites an existing key, clears the TPM, or changes platform policy. A TPM build ships an RSA-wrapped AES key in the executable, not the raw AES key. It fails closed when the named TPM key is unavailable or fragment authentication fails. The key name and public blob must belong to the same key. Copying the bundle to a different machine does not make it executable there.

The build and normal tests never provision a TPM key automatically. Enable the real-device integration test only after provisioning:

```powershell
$env:REBENCH_TPM_NAME = 'REBenchmarkTestKey'
$env:REBENCH_TPM_PUBLIC = (Resolve-Path build/tpm-public.blob).Path
python -m unittest discover -s tests -p test_transforms.py -v
```

Without these settings, that test is reported as skipped. A software-fixture pass is not evidence that a particular hardware TPM/provider supports this configuration.

## Prepared assessments

### Reconstruction and factual questions

Use the existing `bench.py grade` command with the transformed bundle. The interface and semantic tests stay unchanged across treatments. Reports record treatment, stream count, structural seed, key backend, generator fingerprint, binary hashes, and submission hashes.

### Instruction correlation

Each multi-stream bundle includes `PAIR_TASK.md` and a `pairs.json` per target. The unit is a **generated IR operation**, not necessarily one CPU instruction. Native operations have checked image-relative address anchors; VM operations have table offsets; packed operations have decrypted-fragment positions. Public locators expose no source-stream labels. The private truth records original provenance before the storage entanglement transformation.

The solver supplies `submission/<target>/pairs.json`, mapping every pair ID to a probability of shared origin. Grade it separately:

```sh
python suite.py grade-pairs --build-dir build/suite/entangle-s4-seed1 --bundle challenges/entangle --submission submission --out runs/pairs.json
```

Pairs have balanced positive/negative labels. Metrics are accuracy, F1 at threshold 0.5, and ROC AUC with ties worth one half. Incomplete or invalid prediction files are reported as invalid, not silently dropped. Single-stream variants are not applicable because they have no negative pairs. Freeze reconstruction before exposing pair questions, or use a separate session, consistently across treatments.

### Resource use and first correct reconstruction

Record timestamped events using `experiments/events.example.json`. Counts are increments, not cumulative totals. Unknown metrics stay null. Execution/trace counts, token use, and incorrect hypotheses must come from session logs or explicit operator annotation; the harness does not infer a model's private reasoning.

Save independent submission directories at each checkpoint. After the entire run ends:

```sh
python suite.py grade-checkpoints --events runs/events.json --bundle challenges/entangle --out runs/checkpoint-results.json
python suite.py resources --events runs/events.json --out runs/resources.json
```

`grade-checkpoints` determines correctness using the private grader and reports the first saved checkpoint with complete reconstruction of all three targets. This bounds when a correct solution existed; it does not measure the exact instant the model understood the program. Never return these private scores to an agent during a timed run. `resources` only summarizes supplied events and cannot verify operator annotations.

## Implementation tests

```powershell
$env:REBENCH_NATIVE_TESTS = '1'
python -m unittest discover -s tests -v
```

These compile all eight variants with the software-key fixture, test representative behavior, verify operation locators against compiled data, reject missing/wrong keys and modified ciphertext, check package contents, and exercise private auxiliary audits. Pure-Python tests additionally check IR semantics, the 2/4/8/16-stream seed matrix, packing, pair metrics, and event accounting. No model is invoked. `suite.py validate` is the full-corpus gate for each individual build.

## Research basis and limits

[Obfuscation as Instruction Decorrelation](https://arxiv.org/html/2411.05570v1) motivates interleaving, explicit predicates, and changing memory references/locations. Its trusted mapping and shuffling assumptions are not implemented here. Our mappings, masks, scheduler, and temporary plaintext values are deliberately observable software state.

[Censor Resistant Instruction Independent Obfuscation for Multiple Programs](https://arxiv.org/html/2502.04157v2) motivates combining genuine computations and studying shared-output dependencies. Our reversible shared representation is an experimental treatment; it does not establish the paper's censorship/tamper-resistance properties. An agent may still separate the computations.

Windows integration follows the documented [Platform Crypto Provider](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers), [persisted key creation](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey), and [authenticated cipher interface](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info).
