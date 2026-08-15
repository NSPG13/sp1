use alloc::vec;
use alloc::vec::Vec;
use core::array;

use num_bigint::BigUint;

use crate::field::Field;
use crate::{AbstractField, PrimeField, PrimeField31, PrimeField32, TwoAdicField};

/// Computes `Z_H(x)`, where `Z_H` is the zerofier of a multiplicative subgroup of order `2^log_n`.
pub fn two_adic_subgroup_zerofier<F: TwoAdicField>(log_n: usize, x: F) -> F {
    x.exp_power_of_2(log_n) - F::one()
}

/// Computes `Z_{sH}(x)`, where `Z_{sH}` is the zerofier of the given coset of a multiplicative
/// subgroup of order `2^log_n`.
pub fn two_adic_coset_zerofier<F: TwoAdicField>(log_n: usize, shift: F, x: F) -> F {
    x.exp_power_of_2(log_n) - shift.exp_power_of_2(log_n)
}

/// Computes a multiplicative subgroup whose order is known in advance.
pub fn cyclic_subgroup_known_order<F: Field>(
    generator: F,
    order: usize,
) -> impl Iterator<Item = F> + Clone {
    generator.powers().take(order)
}

/// Computes a coset of a multiplicative subgroup whose order is known in advance.
pub fn cyclic_subgroup_coset_known_order<F: Field>(
    generator: F,
    shift: F,
    order: usize,
) -> impl Iterator<Item = F> + Clone {
    cyclic_subgroup_known_order(generator, order).map(move |x| x * shift)
}

#[must_use]
pub fn add_vecs<F: Field>(v: Vec<F>, w: Vec<F>) -> Vec<F> {
    assert_eq!(v.len(), w.len());
    v.into_iter().zip(w).map(|(x, y)| x + y).collect()
}

pub fn sum_vecs<F: Field, I: Iterator<Item = Vec<F>>>(iter: I) -> Vec<F> {
    iter.reduce(|v, w| add_vecs(v, w)).expect("sum_vecs: empty iterator")
}

pub fn scale_vec<F: Field>(s: F, vec: Vec<F>) -> Vec<F> {
    vec.into_iter().map(|x| s * x).collect()
}

/// `x += y * s`, where `s` is a scalar.
pub fn add_scaled_slice_in_place<F, Y>(x: &mut [F], y: Y, s: F)
where
    F: Field,
    Y: Iterator<Item = F>,
{
    // TODO: Use PackedField
    x.iter_mut().zip(y).for_each(|(x_i, y_i)| *x_i += y_i * s);
}

/// Extend a field `AF` element `x` to an array of length `D`
/// by filling zeros.
pub fn field_to_array<AF: AbstractField, const D: usize>(x: AF) -> [AF; D] {
    let mut arr = array::from_fn(|_| AF::zero());
    arr[0] = x;
    arr
}

/// Naive polynomial multiplication.
pub fn naive_poly_mul<AF: AbstractField>(a: &[AF], b: &[AF]) -> Vec<AF> {
    // Grade school algorithm
    let mut product = vec![AF::zero(); a.len() + b.len() - 1];
    for (i, c1) in a.iter().enumerate() {
        for (j, c2) in b.iter().enumerate() {
            product[i + j] += c1.clone() * c2.clone();
        }
    }
    product
}

/// Expand a product of binomials (x - roots[0])(x - roots[1]).. into polynomial coefficients.
pub fn binomial_expand<AF: AbstractField>(roots: &[AF]) -> Vec<AF> {
    let mut coeffs = vec![AF::zero(); roots.len() + 1];
    coeffs[0] = AF::one();
    for (i, x) in roots.iter().enumerate() {
        for j in (1..i + 2).rev() {
            coeffs[j] = coeffs[j - 1].clone() - x.clone() * coeffs[j].clone();
        }
        coeffs[0] *= -x.clone();
    }
    coeffs
}

pub fn eval_poly<AF: AbstractField>(poly: &[AF], x: AF) -> AF {
    let mut acc = AF::zero();
    for coeff in poly.iter().rev() {
        acc *= x.clone();
        acc += coeff.clone();
    }
    acc
}

/// Given an element x from a 32 bit field F_P compute x/2.
#[inline]
pub fn halve_u32<const P: u32>(input: u32) -> u32 {
    let shift = (P + 1) >> 1;
    let shr = input >> 1;
    let lo_bit = input & 1;
    let shr_corr = shr + shift;
    if lo_bit == 0 {
        shr
    } else {
        shr_corr
    }
}

/// Given an element x from a 64 bit field F_P compute x/2.
#[inline]
pub fn halve_u64<const P: u64>(input: u64) -> u64 {
    let shift = (P + 1) >> 1;
    let shr = input >> 1;
    let lo_bit = input & 1;
    let shr_corr = shr + shift;
    if lo_bit == 0 {
        shr
    } else {
        shr_corr
    }
}

/// Given a slice of SF elements, reduce them to a TF element using a 2^32-base decomposition.
pub fn reduce_31<SF: PrimeField31, TF: PrimeField>(vals: &[SF]) -> TF {
    let po2 = TF::from_canonical_u64(1u64 << 31);
    let mut result = TF::zero();
    for val in vals.iter().rev() {
        result = result * po2 + TF::from_canonical_u32(val.as_canonical_u32());
    }
    result
}

/// Smallest radix width that represents every canonical 32-bit field value.
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

/// Number of near-uniform base-field-order limbs retained from a target word.
#[must_use]
pub fn squeeze_field_order_num_limbs<PF: PrimeField, F: PrimeField32>() -> usize {
    let base = BigUint::from(F::ORDER_U32);
    let target_order = PF::order();
    let mut count = 0usize;
    let mut power = BigUint::from(1u32);
    while &power * &base < target_order {
        power *= &base;
        count += 1;
    }
    count.saturating_sub(1)
}

/// Splits a target word into little-endian base-`F::ORDER_U32` limbs.
#[must_use]
pub fn split_pf_to_field_order_limbs<PF: PrimeField, F: PrimeField32>(
    value: PF,
    num_limbs: usize,
) -> Vec<F> {
    let base = F::ORDER_U32;
    let mut remaining = value.as_canonical_biguint();
    let mut output = Vec::with_capacity(num_limbs);
    for _ in 0..num_limbs {
        let limb = (&remaining % base).to_u32_digits().first().copied().unwrap_or(0);
        output.push(F::from_canonical_u32(limb));
        remaining /= base;
    }
    output
}

/// Given an SF element, split it to a vector of TF elements using a 2^64-base decomposition.
///
/// We use a 2^64-base decomposition for a field of size ~2^32 because then the bias will be
/// at most ~1/2^32 for each element after the reduction.
pub fn split_32<SF: PrimeField, TF: PrimeField32>(val: SF, n: usize) -> Vec<TF> {
    let po2 = BigUint::from(1u128 << 64);
    let mut val = val.as_canonical_biguint();
    let mut result = Vec::new();
    for _ in 0..n {
        let mask: BigUint = po2.clone() - BigUint::from(1u128);
        let digit: BigUint = val.clone() & mask;
        let digit_u64s = digit.to_u64_digits();
        if !digit_u64s.is_empty() {
            result.push(TF::from_wrapped_u64(digit_u64s[0]));
        } else {
            result.push(TF::zero())
        }
        val /= po2.clone();
    }
    result
}
