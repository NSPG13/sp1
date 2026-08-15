# agent-bounties-sp1-safe-v2

This circuit identity supersedes `agent-bounties-sp1-safe-v1` before deployment.
The challenger implementation is unchanged from safe-v1, but the wrap template
proof is regenerated under the injective transcript and both wrap artifacts are
hash-bound in the release manifest. The regenerated wrap verification key is
byte-identical because the circuit shape is unchanged. Verifier assets built with
the upstream v6.4.0 template proof are invalid for this circuit.

Release order:

1. Build a deterministic guest ELF with the pinned SP1 toolchain.
2. Run `regenerate_wrap_template` with that ELF and its exact SHA-256 digest.
3. Verify `crates/prover/wrap_vk.bin` and replace `crates/prover/wrapped_proof.bin`.
4. Commit the generated `wrap-template-manifest.json` beside the binaries.
5. Build Groth16 and PLONK assets from this exact source tree.

GPU proving remains disabled for this release.
