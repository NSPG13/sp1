use std::borrow::Borrow;

use serde_json::Value;
use sha2::{Digest, Sha256};
use slop_challenger::IopCtx;
use sp1_hypercube::{koalabears_to_bn254, MachineVerifyingKey, SP1PcsProofOuter, ShardProof};
use sp1_primitives::{SP1Field, SP1OuterGlobalContext};
use sp1_prover::{verify::WRAP_VK_BYTES, CpuSP1ProverComponents, SP1ProverComponents};
use sp1_recursion_executor::RecursionPublicValues;

const WRAPPED_PROOF_BYTES: &[u8] = include_bytes!("../wrapped_proof.bin");
const WRAP_TEMPLATE_MANIFEST: &str = include_str!("../wrap-template-manifest.json");

fn main() {
    let manifest: Value =
        serde_json::from_str(WRAP_TEMPLATE_MANIFEST).expect("invalid wrap template manifest");
    assert_eq!(
        manifest["circuit_version"].as_str(),
        Some(include_str!("../../../SP1_CIRCUIT_VERSION").trim()),
        "wrap template circuit identity mismatch"
    );
    let wrap_vk_sha256 = hex::encode(Sha256::digest(WRAP_VK_BYTES));
    assert_eq!(
        manifest["wrap_vk_sha256"].as_str(),
        Some(wrap_vk_sha256.as_str()),
        "wrap vkey hash mismatch"
    );
    let wrapped_proof_sha256 = hex::encode(Sha256::digest(WRAPPED_PROOF_BYTES));
    assert_eq!(
        manifest["wrapped_proof_sha256"].as_str(),
        Some(wrapped_proof_sha256.as_str()),
        "wrapped proof hash mismatch"
    );

    let vk: MachineVerifyingKey<SP1OuterGlobalContext> =
        bincode::deserialize(WRAP_VK_BYTES).expect("failed to deserialize wrap verification key");
    let proof: ShardProof<SP1OuterGlobalContext, SP1PcsProofOuter> =
        bincode::deserialize(WRAPPED_PROOF_BYTES).expect("failed to deserialize wrapped proof");
    let mut challenger = SP1OuterGlobalContext::default_challenger();
    vk.observe_into(&mut challenger);
    CpuSP1ProverComponents::wrap_verifier()
        .verify_shard(&vk, &proof, &mut challenger)
        .expect("committed wrap template proof is invalid");
    let public_values: &RecursionPublicValues<SP1Field> = proof.public_values.as_slice().borrow();
    println!("sp1_vk_digest={:?}", public_values.sp1_vk_digest);
    println!("sp1_vk_digest_bn254={}", koalabears_to_bn254(&public_values.sp1_vk_digest));
    println!("committed wrap template proof is valid");
}
