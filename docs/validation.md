# Preparation validation

Validation performed on Windows with GCC/G++ and Python. No AI solver or model benchmark was run for this branch.

- 21 automated tests: 20 passed; the positive hardware TPM round-trip test was skipped because no dedicated TPM test key was configured.
- All eight variants built for all three targets: 24 ordinary binaries plus their author-only audit builds.
- Single-stream controls used seed 1; multi-stream prepared bundles used four streams and seed 1.
- Every prepared binary and audit build passed the complete existing reference corpus: 2,546 pricing cases, 340 record cases, and 84 session transcripts per variant.
- Native tests also exercised two streams and the entangled representation at 4, 8, and 16 streams. Structural generation tests covered seeds 1 through 5 at every supported strength.
- Software-key full-stack tests rejected missing keys, incorrect keys, and modified ciphertext.
- The real Windows TPM build path compiled and correctly refused execution without its named key. No fallback provider was used, and no TPM key was provisioned by the tests.
- Operation locators, balanced pair labels, AUC/F1 calculations, event accounting, and package exclusion of private files passed their checks.

Prepared local artifacts are under `build/prepared/` and `challenges/prepared/`. They are ignored by Git and can be regenerated using the [suite instructions](transformations.md). The full-stack prepared bundle uses the explicitly labeled software-key fixture. The complete 252-binary experiment matrix is specified, not built or benchmarked.

These results establish implementation correctness on the tested inputs. They do not establish resistance to reverse engineering, instruction independence, or positive hardware TPM compatibility.
