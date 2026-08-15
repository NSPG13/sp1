# agent-bounties-sp1-safe-v4

This circuit identity supersedes `agent-bounties-sp1-safe-v3` before deployment.
Safe-v3 regenerated the wrap proof under the injective transcript, but its
recursive `observe_commitment` implementation aliased the observed digest into
the in-place Poseidon state. The permutation therefore mutated a digest that
later verification expected to remain immutable. Native Rust uses value copies,
so the exported circuit diverged from its witness.

Safe-v4 copies commitment variables into fresh circuit variables before every
in-place permutation. It retains the source-pinned transcript hardening, the
deterministic guest ELF, and the hash-bound wrap-template manifest.

Release order:

1. Run the native-versus-circuit transcript and commitment-preservation tests.
2. Regenerate and self-verify the deterministic wrap template.
3. Rebuild Groth16 and PLONK constraints and verifier assets from this source.
4. Generate real proofs and verify them in Rust, Gnark and Solidity.
5. Publish immutable source and artifact hashes only after both systems pass.

Circuit setup requires an x86-64 Linux host with at least 250 GiB reported
physical memory and 60 GiB free disk. The measured Groth16 peak was about
247 GiB resident memory. Swap is emergency headroom and does not qualify an
undersized release builder.

Groth16 setup consumes operating-system CSPRNG entropy. A second setup is not
expected to reproduce the proving key, verifying key, or exported verifier.
Instead, isolated builders must reproduce the exact constraint hash and compile
the frozen exported verifier source to identical bytecode. The one-time proving
and verifying keys, verifier source, and setup evidence are immutable,
content-addressed release artifacts.

GPU proving remains disabled for this release. The setup host must not be
snapshotted and must be destroyed after the hash-pinned artifacts are moved to
the segregated proving service.
