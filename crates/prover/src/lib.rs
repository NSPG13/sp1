pub mod build;
mod components;
pub mod recursion;
pub mod shapes;
mod types;
pub mod utils;
pub mod verify;
pub mod worker;

pub use types::*;

pub use components::*;

/// The global version for all components of SP1.
///
/// This string should be updated whenever any step in verifying an SP1 proof changes, including
/// core, recursion, and plonk-bn254. This string is used to download SP1 artifacts and the gnark
/// docker image.
pub const SP1_CIRCUIT_VERSION: &str = "agent-bounties-sp1-safe-v5";

#[cfg(test)]
mod tests {
    use super::SP1_CIRCUIT_VERSION;

    #[test]
    fn circuit_version_matches_release_file_and_has_no_whitespace() {
        let release_file = include_str!("../SP1_CIRCUIT_VERSION");
        assert_eq!(release_file.trim(), SP1_CIRCUIT_VERSION);
        assert!(!SP1_CIRCUIT_VERSION.chars().any(char::is_whitespace));
    }
}

pub use sp1_hypercube::{HashableKey, SP1VerifyingKey};
