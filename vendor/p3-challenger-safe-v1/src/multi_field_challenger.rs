use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use num_bigint::BigUint;
use p3_field::{ExtensionField, PrimeField, PrimeField31, PrimeField32};
use p3_symmetric::{CryptographicPermutation, Hash};
use serde::{Deserialize, Serialize};

use crate::{CanObserve, CanSample, CanSampleBits, FieldChallenger};

/// Smallest radix width that represents every canonical source-field value.
#[inline]
#[must_use]
pub const fn absorb_radix_bits<F: PrimeField32>() -> u32 {
    u32::BITS - (F::ORDER_U32 - 1).leading_zeros()
}

/// Packs canonical source-field limbs without reduction in the target field.
#[must_use]
pub fn reduce_packed<SF: PrimeField32, TF: PrimeField>(vals: &[SF], radix_bits: u32) -> TF {
    debug_assert!(absorb_radix_bits::<SF>() <= radix_bits && radix_bits < 64);
    let base = TF::from_canonical_u64(1u64 << radix_bits);
    vals.iter().rev().fold(TF::zero(), |acc, value| {
        acc * base + TF::from_canonical_u32(value.as_canonical_u32())
    })
}

/// Maximum source-field limbs that fit injectively in one target-field word.
#[must_use]
pub fn max_absorb_injective_limbs<F: PrimeField32, PF: PrimeField>() -> usize {
    let radix_bits = absorb_radix_bits::<F>();
    let max_digit = BigUint::from(F::ORDER_U32 - 1);
    let base = BigUint::from(1u32) << radix_bits as usize;
    let target_order = PF::order();
    let mut limbs = 0usize;
    let mut max_value = BigUint::from(0u32);
    let mut power = BigUint::from(1u32);
    loop {
        let candidate = &max_value + &max_digit * &power;
        if candidate >= target_order {
            return limbs;
        }
        max_value = candidate;
        power *= &base;
        limbs += 1;
    }
}

/// Bit width for an injective target-word digit in the source field.
#[inline]
#[must_use]
pub const fn squeeze_limb_bits<F: PrimeField32>() -> u32 {
    u32::BITS - 1 - (F::ORDER_U32 - 1).leading_zeros()
}

/// Number of fixed-width source-field limbs required to retain a target word.
#[must_use]
pub fn squeeze_field_order_num_limbs<PF: PrimeField, F: PrimeField32>() -> usize {
    let limb_bits = squeeze_limb_bits::<F>() as usize;
    (PF::order().bits() as usize).div_ceil(limb_bits)
}

/// Splits a target word into little-endian fixed-width limbs without reduction.
#[must_use]
pub fn split_pf_to_field_order_limbs<PF: PrimeField, F: PrimeField32>(
    value: PF,
    num_limbs: usize,
) -> Vec<F> {
    let limb_bits = squeeze_limb_bits::<F>() as usize;
    let mask = (BigUint::from(1u32) << limb_bits) - BigUint::from(1u32);
    let mut remaining = value.as_canonical_biguint();
    let mut output = Vec::with_capacity(num_limbs);
    for _ in 0..num_limbs {
        let limb = (&remaining & &mask).to_u32_digits().first().copied().unwrap_or(0);
        output.push(F::from_canonical_u32(limb));
        remaining >>= limb_bits;
    }
    debug_assert_eq!(remaining, BigUint::from(0u32));
    output
}

/// A challenger that operates natively on PF but produces challenges of F: PrimeField32.
///
/// Used for optimizing the cost of recursive proof verification of STARKs in SNARKs.
///
/// Scalar absorbs are injectively packed, exact-length tagged, and zero padded.
/// Native digest words are absorbed without lossy field conversion. Squeezed
/// values use fixed-width injective limbs over the complete target-field domain.
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
