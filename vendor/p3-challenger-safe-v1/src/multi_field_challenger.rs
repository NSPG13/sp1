use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use p3_field::{
    absorb_radix_bits, max_absorb_injective_limbs, reduce_packed, split_pf_to_field_order_limbs,
    squeeze_field_order_num_limbs, ExtensionField, PrimeField, PrimeField31, PrimeField32,
};
use p3_symmetric::{CryptographicPermutation, Hash};
use serde::{Deserialize, Serialize};

use crate::{CanObserve, CanSample, CanSampleBits, FieldChallenger};

/// A challenger that operates natively on PF but produces challenges of F: PrimeField32.
///
/// Used for optimizing the cost of recursive proof verification of STARKs in SNARKs.
///
/// Scalar absorbs are injectively packed, exact-length tagged, and zero padded.
/// Native digest words are absorbed without lossy field conversion. Squeezed
/// values use base-field-order limbs over the complete `F` domain.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "[PF; WIDTH]: Serialize, P: Serialize"))]
#[serde(bound(deserialize = "[PF; WIDTH]: Deserialize<'de>, P: Deserialize<'de>"))]
pub struct MultiField32Challenger<F, PF, P, const WIDTH: usize, const RATE: usize>
where
    F: PrimeField32,
    PF: PrimeField,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    pub sponge_state: [PF; WIDTH],
    pub input_buffer: Vec<F>,
    pub output_buffer: Vec<F>,
    pub permutation: P,
    pub num_duplex_elms: usize,
    pub num_f_elms: usize,
}

impl<F, PF, P, const WIDTH: usize, const RATE: usize> MultiField32Challenger<F, PF, P, WIDTH, RATE>
where
    F: PrimeField32,
    PF: PrimeField,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    pub fn new(permutation: P) -> Result<Self, String> {
        if F::order() >= PF::order() {
            return Err(String::from("F::order() must be less than PF::order()"));
        }
        if RATE >= WIDTH {
            return Err(String::from("RATE must leave one capacity slot"));
        }
        let num_duplex_elms = max_absorb_injective_limbs::<F, PF>();
        let num_f_elms = squeeze_field_order_num_limbs::<PF, F>();
        if num_duplex_elms == 0 || num_f_elms == 0 || num_duplex_elms * RATE > u8::MAX as usize {
            return Err(String::from("unsupported field packing parameters"));
        }
        Ok(Self {
            sponge_state: [PF::default(); WIDTH],
            input_buffer: vec![],
            output_buffer: vec![],
            permutation,
            num_duplex_elms,
            num_f_elms,
        })
    }
}

impl<F, PF, P, const WIDTH: usize, const RATE: usize> MultiField32Challenger<F, PF, P, WIDTH, RATE>
where
    F: PrimeField31,
    PF: PrimeField,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    fn duplexing(&mut self) {
        assert!(self.input_buffer.len() <= self.num_duplex_elms * RATE);
        if self.input_buffer.is_empty() {
            self.permutation.permute_mut(&mut self.sponge_state);
        } else {
            let input_len = self.input_buffer.len();
            let radix_bits = absorb_radix_bits::<F>();
            let packed = self
                .input_buffer
                .chunks(self.num_duplex_elms)
                .map(|chunk| reduce_packed::<F, PF>(chunk, radix_bits))
                .collect::<Vec<_>>();
            for (index, value) in packed.iter().copied().enumerate() {
                self.sponge_state[index] = value;
            }
            self.sponge_state[packed.len()..RATE].fill(PF::zero());
            self.sponge_state[RATE] += PF::from_canonical_u8(input_len as u8);
            self.permutation.permute_mut(&mut self.sponge_state);
        }
        self.input_buffer.clear();

        self.output_buffer.clear();
        for &pf_val in self.sponge_state[0..RATE].iter() {
            let f_vals = split_pf_to_field_order_limbs(pf_val, self.num_f_elms);
            for f_val in f_vals {
                self.output_buffer.push(f_val);
            }
        }
    }
}

impl<F, PF, P, const WIDTH: usize, const RATE: usize> FieldChallenger<F>
    for MultiField32Challenger<F, PF, P, WIDTH, RATE>
where
    F: PrimeField31,
    PF: PrimeField,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
}

impl<F, PF, P, const WIDTH: usize, const RATE: usize> CanObserve<F>
    for MultiField32Challenger<F, PF, P, WIDTH, RATE>
where
    F: PrimeField31,
    PF: PrimeField,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    fn observe(&mut self, value: F) {
        // Any buffered output is now invalid.
        self.output_buffer.clear();

        self.input_buffer.push(value);

        if self.input_buffer.len() == self.num_duplex_elms * RATE {
            self.duplexing();
        }
    }
}

impl<F, PF, const N: usize, P, const WIDTH: usize, const RATE: usize> CanObserve<[F; N]>
    for MultiField32Challenger<F, PF, P, WIDTH, RATE>
where
    F: PrimeField31,
    PF: PrimeField,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    fn observe(&mut self, values: [F; N]) {
        for value in values {
            self.observe(value);
        }
    }
}

impl<F, PF, const N: usize, P, const WIDTH: usize, const RATE: usize> CanObserve<Hash<F, PF, N>>
    for MultiField32Challenger<F, PF, P, WIDTH, RATE>
where
    F: PrimeField31,
    PF: PrimeField,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    fn observe(&mut self, values: Hash<F, PF, N>) {
        self.output_buffer.clear();
        if !self.input_buffer.is_empty() {
            self.duplexing();
        }
        for chunk in values.as_ref().chunks(RATE) {
            for (index, value) in chunk.iter().copied().enumerate() {
                self.sponge_state[index] = value;
            }
            self.sponge_state[chunk.len()..RATE].fill(PF::zero());
            self.sponge_state[RATE] += PF::from_canonical_u8(chunk.len() as u8);
            self.permutation.permute_mut(&mut self.sponge_state);
            self.output_buffer.clear();
            for &pf_val in &self.sponge_state[..RATE] {
                self.output_buffer
                    .extend(split_pf_to_field_order_limbs::<PF, F>(pf_val, self.num_f_elms));
            }
        }
    }
}

// for TrivialPcs
impl<F, PF, P, const WIDTH: usize, const RATE: usize> CanObserve<Vec<Vec<F>>>
    for MultiField32Challenger<F, PF, P, WIDTH, RATE>
where
    F: PrimeField31,
    PF: PrimeField,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    fn observe(&mut self, valuess: Vec<Vec<F>>) {
        for values in valuess {
            for value in values {
                self.observe(value);
            }
        }
    }
}

impl<F, EF, PF, P, const WIDTH: usize, const RATE: usize> CanSample<EF>
    for MultiField32Challenger<F, PF, P, WIDTH, RATE>
where
    F: PrimeField31,
    EF: ExtensionField<F>,
    PF: PrimeField,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    fn sample(&mut self) -> EF {
        EF::from_base_fn(|_| {
            // If we have buffered inputs, we must perform a duplexing so that the challenge will
            // reflect them. Or if we've run out of outputs, we must perform a duplexing to get more.
            if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
                self.duplexing();
            }

            self.output_buffer.pop().expect("Output buffer should be non-empty")
        })
    }
}

impl<F, PF, P, const WIDTH: usize, const RATE: usize> CanSampleBits<usize>
    for MultiField32Challenger<F, PF, P, WIDTH, RATE>
where
    F: PrimeField31,
    PF: PrimeField,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    fn sample_bits(&mut self, bits: usize) -> usize {
        debug_assert!(bits < (usize::BITS as usize));
        debug_assert!((1 << bits) < F::ORDER_U64);
        let rand_f: F = self.sample();
        let rand_usize = rand_f.as_canonical_u64() as usize;
        rand_usize & ((1 << bits) - 1)
    }
}
