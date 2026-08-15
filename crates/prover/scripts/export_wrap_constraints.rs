use std::{fs, path::PathBuf};

use clap::Parser;
use sp1_core_machine::utils::setup_logger;
use sp1_hypercube::{MachineVerifyingKey, SP1PcsProofOuter, ShardProof};
use sp1_primitives::SP1OuterGlobalContext;
use sp1_prover::{build::build_constraints_and_witness, verify::WRAP_VK_BYTES};
use sp1_recursion_gnark_ffi::GnarkWitness;

const WRAPPED_PROOF_BYTES: &[u8] = include_bytes!("../wrapped_proof.bin");

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long)]
    output_dir: PathBuf,
}

fn main() {
    setup_logger();
    let args = Args::parse();
    fs::create_dir_all(&args.output_dir).expect("failed to create output directory");

    let wrap_vk: MachineVerifyingKey<SP1OuterGlobalContext> =
        bincode::deserialize(WRAP_VK_BYTES).expect("failed to deserialize wrap vk");
    let wrapped_proof: ShardProof<SP1OuterGlobalContext, SP1PcsProofOuter> =
        bincode::deserialize(WRAPPED_PROOF_BYTES).expect("failed to deserialize wrapped proof");
    let (constraints, witness) =
        build_constraints_and_witness(&wrap_vk, &wrapped_proof).expect("failed to build circuit");

    let constraints = serde_json::to_vec(&constraints).expect("failed to serialize constraints");
    fs::write(args.output_dir.join("constraints.json"), constraints)
        .expect("failed to write constraints");
    let witness =
        serde_json::to_vec(&GnarkWitness::new(witness)).expect("failed to serialize witness");
    fs::write(args.output_dir.join("witness.json"), witness).expect("failed to write witness");
}
