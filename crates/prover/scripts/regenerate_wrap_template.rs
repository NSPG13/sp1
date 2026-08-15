use std::{borrow::Borrow, path::PathBuf};

use clap::Parser;
use serde_json::json;
use sha2::{Digest, Sha256};
use slop_challenger::IopCtx;
use sp1_core_executor::SP1Context;
use sp1_core_machine::{io::SP1Stdin, riscv::RiscvAir, utils::setup_logger};
use sp1_hypercube::HashableKey;
use sp1_primitives::{SP1Field, SP1OuterGlobalContext};
use sp1_prover::worker::{cpu_worker_builder_with_machine, SP1LocalNodeBuilder};
use sp1_prover::{CpuSP1ProverComponents, SP1ProverComponents};
use sp1_prover_types::network_base_types::ProofMode;
use sp1_recursion_circuit::machine::RootPublicValues;

/// Rebuilds the wrap verification key and template proof for this exact circuit source.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// A deterministic SP1 guest ELF used to generate the template proof.
    #[arg(long)]
    elf: PathBuf,

    /// Lowercase SHA-256 digest of the exact template ELF.
    #[arg(long)]
    expected_elf_sha256: String,

    /// Directory that will receive wrap_vk.bin and wrapped_proof.bin.
    #[arg(long)]
    output_dir: PathBuf,
}

#[tokio::main]
async fn main() {
    setup_logger();
    let args = Args::parse();
    let elf = std::fs::read(&args.elf).expect("failed to read template ELF");
    let elf_sha256 = hex::encode(Sha256::digest(&elf));
    assert_eq!(elf_sha256, args.expected_elf_sha256, "template ELF hash mismatch");

    let machine = RiscvAir::machine();
    let client =
        SP1LocalNodeBuilder::from_worker_client_builder(cpu_worker_builder_with_machine(machine))
            .build()
            .await
            .expect("failed to build local prover");
    let vk = client.setup(&elf).await.expect("failed to derive template guest vkey");

    let compressed_proof = client
        .prove_with_mode(&elf, SP1Stdin::new(), SP1Context::default(), ProofMode::Compressed)
        .await
        .expect("failed to produce compressed template proof");
    let wrapped =
        client.shrink_wrap(&compressed_proof.proof).await.expect("failed to shrink-wrap proof");
    let mut challenger = SP1OuterGlobalContext::default_challenger();
    wrapped.vk.observe_into(&mut challenger);
    CpuSP1ProverComponents::wrap_verifier()
        .verify_shard(&wrapped.vk, &wrapped.proof, &mut challenger)
        .expect("generated wrap template proof failed native verification");
    let public_values: &RootPublicValues<SP1Field> =
        wrapped.proof.public_values.as_slice().borrow();
    assert_eq!(
        *public_values.vk_root(),
        client.core().recursion_vks().root(),
        "generated wrap template has a stale recursion-vkey root"
    );
    assert_eq!(
        *public_values.sp1_vk_digest(),
        vk.hash_koalabear(),
        "generated wrap template is not bound to the template guest vkey"
    );

    std::fs::create_dir_all(&args.output_dir).expect("failed to create output directory");
    let wrap_vk =
        bincode::serialize(&wrapped.vk).expect("failed to serialize wrap verification key");
    let wrapped_proof =
        bincode::serialize(&wrapped.proof).expect("failed to serialize wrapped proof");
    std::fs::write(args.output_dir.join("wrap_vk.bin"), &wrap_vk)
        .expect("failed to write wrap verification key");
    std::fs::write(args.output_dir.join("wrapped_proof.bin"), &wrapped_proof)
        .expect("failed to write wrapped proof");

    let manifest = json!({
        "schema": "agent-bounties/sp1-wrap-template-v1",
        "circuit_version": include_str!("../../../SP1_CIRCUIT_VERSION").trim(),
        "template_elf_sha256": elf_sha256,
        "wrap_vk_sha256": hex::encode(Sha256::digest(&wrap_vk)),
        "wrapped_proof_sha256": hex::encode(Sha256::digest(&wrapped_proof)),
    });
    std::fs::write(
        args.output_dir.join("wrap-template-manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("failed to serialize wrap template manifest"),
    )
    .expect("failed to write wrap template manifest");
}
