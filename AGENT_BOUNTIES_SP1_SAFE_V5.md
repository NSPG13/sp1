# agent-bounties-sp1-safe-v5

This circuit identity supersedes `agent-bounties-sp1-safe-v4` before deployment.
Safe-v4 retained every squeeze bit by repeatedly dividing a BN254 word by the
KoalaBear field order inside the recursive circuit. The encoding was injective,
but it expanded the PLONK circuit to 95,505,605 constraints and therefore a
2^27 evaluation domain. SP1 v6.4.0's pinned Aztec Ignition SRS contains
100,800,000 G1 powers and cannot serve that domain.

Safe-v5 decomposes each canonical BN254 word once and emits nine little-endian
30-bit limbs. Every limb is strictly below the KoalaBear modulus, and 270 bits
cover every 254-bit BN254 value, so the encoding is injective without modular
reduction or repeated long division. Native and recursive challengers use the
same encoding. The advisory regression now changes bit 240 to prove that the
highest source-word region affects the challenge.

Release order:

1. Run native-versus-circuit transcript tests and all three advisory vectors.
2. Regenerate and self-verify the deterministic wrap template.
3. Confirm the compiled PLONK domain fits the pinned SRS before setup.
4. Rebuild Groth16 and PLONK constraints and immutable verifier assets.
5. Generate real proofs and verify them in Rust, Gnark and Solidity.
6. Publish immutable source and artifact hashes only after both systems pass.

GPU proving remains disabled. Setup artifacts are accepted only with exact
source, circuit, transcript, constraint and verifier hashes.
