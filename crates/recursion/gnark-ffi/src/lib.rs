mod koalabear;

pub mod ffi;
pub mod groth16_bn254;
pub mod plonk_bn254;
pub mod proof;
pub mod witness;

pub use groth16_bn254::*;
pub use plonk_bn254::*;
pub use proof::*;
pub use witness::*;

/// The global version for all components of SP1.
///
/// This string should be updated whenever any step in verifying an SP1 proof changes, including
/// core, recursion, and plonk-bn254. This string is used to download SP1 artifacts and the gnark
/// docker image.
const SP1_CIRCUIT_VERSION: &str = "agent-bounties-sp1-safe-v2";

#[cfg(test)]
mod tests {
    use super::SP1_CIRCUIT_VERSION;

    #[test]
    fn circuit_version_matches_release_file_and_is_a_valid_tag() {
        let release_file = include_str!("../assets/SP1_CIRCUIT_VERSION");
        assert_eq!(release_file.trim(), SP1_CIRCUIT_VERSION);
        assert!(!SP1_CIRCUIT_VERSION.chars().any(char::is_whitespace));
    }
}
