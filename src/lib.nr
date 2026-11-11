use std::ops::Neg;

use bignum::{bignum::BigNum, ED25519_Fr as Fr};
use edwards_bignum::{CurveTrait, ScalarField, TECurveParameterTrait};
use edwards_bignum::ed25519::{Ed25519, Ed25519Params};
use sha512::sha512;

// The Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493
// (RFC 8032 5.1). Split at 2^128, its high half is 2^124 and its low half is
// L_LO, so a 256-bit little-endian integer can be compared against it exactly,
// without reduction modulo the (254-bit) native field modulus.
global L_LO: u128 = 0x14def9dea2f79cd65812631a5cf5d3ed;
global L_HI: Field = 0x10000000000000000000000000000000;
global TWO_POW_128: Field = 0x100000000000000000000000000000000;

/// Verify an Ed25519 signature (RFC 8032 5.1.7).
///
/// `sig_s_bytes` is the signature's second half: the scalar S as 32
/// little-endian bytes, its RFC 8032 wire form. S >= L is rejected on the
/// 256-bit integer the bytes encode, before any reduction modulo the 254-bit
/// native field modulus p, so the encodings of S + L, S + p and S + 2p are
/// not accepted.
///
/// Two limits come from `edwards_bignum`'s `ScalarField::from`. Both go away
/// once the `edwards_bignum` dependency is updated to a release that includes
/// its decomposition fix, https://github.com/willemolding/noir-edwards-bignum/pull/3.
/// Until then:
/// - `from` also accepts the windows of S - p, S - 2p, S - 3p and S - 4p in
///   place of those of S, so the scalar multiplication is not bound to the
///   checked S, and a valid signature has up to four more accepted scalars,
///   (S + k*p) mod L for k = 1..4.
/// - `from` rejects the honest decomposition of a few values, zero among them,
///   so bytes that encode a multiple of p abort instead of returning false.
pub fn ed25519_verify<let MSG_MAX_LEN: u32>(
    pubkey: Ed25519,
    sig_s_bytes: [u8; 32],
    sig_point: Ed25519,
    message: BoundedVec<u8, MSG_MAX_LEN>,
) -> bool {
    pubkey.assert_is_on_curve();
    sig_point.assert_is_on_curve();

    // Reject small-order / identity public keys: 8A == O iff ord(A) divides the
    // cofactor (8), so this rules out all torsion-only keys, for which the check
    // below would otherwise hold for any message.
    assert(!pubkey.dbl().dbl().dbl().is_zero());

    // Reject S >= L (RFC 8032 5.1.7), as S + L also satisfies the group equation.
    // The comparison is exact over the integers, so it never mistakes the bytes
    // of S + L or S + p for S. `ScalarField::from` must then bind the windows
    // to `s` as an integer (see the limits above).
    let (s, s_in_range) = decode_s(sig_s_bytes);
    let sig_scalar: ScalarField<64> = ScalarField::from(s);

    let mut preimage: BoundedVec<u8, 32 + 32 + MSG_MAX_LEN> = BoundedVec::new();
    preimage.extend_from_array(compress(sig_point));
    preimage.extend_from_array(compress(pubkey));
    preimage.extend_from_bounded_vec(message);

    let k = reduce_wide(sha512::sha512_var(preimage));

    // Check the cofactored group equation [8][s]B == [8]R + [8][k]A
    // (RFC 8032 5.1.7), rewritten as [8]([s]B + [k](-A)) == [8]R so the two
    // scalar multiplications share a single doubling ladder via an MSM.
    //
    // Multiplying both sides by the cofactor (8 = three doublings) clears any
    // order-8 torsion component in A or R.
    let basepoint = Ed25519::from(Ed25519Params::gen());
    let lhs = Ed25519::msm([basepoint, pubkey.neg()], [sig_scalar, k]);
    s_in_range & (lhs.dbl().dbl().dbl() == sig_point.dbl().dbl().dbl())
}

/// Decode a 32-byte little-endian integer S into its value modulo the native
/// field modulus p, and the integer comparison `S < L`.
///
/// Write S = hi * 2^128 + lo, where hi and lo are the integers of the top and
/// bottom 16 bytes. Both are below 2^128 < p, so they are exact as Fields and
/// `lo as u128` loses nothing. With L = 2^124 * 2^128 + L_LO and L_LO < 2^128,
/// S < L exactly when hi < 2^124, or hi = 2^124 and lo < L_LO. hi < 2^124
/// exactly when its top byte, bytes[31], is below 16: the other 15 bytes of hi
/// contribute less than 2^120. An encoding of S + p is therefore seen as the
/// integer S + p (> L), never as S. The returned Field equals S whenever the
/// bool is true, because then S < L < p.
fn decode_s(bytes: [u8; 32]) -> (Field, bool) {
    let mut lo: Field = 0;
    let mut hi: Field = 0;
    for i in 0..16 {
        lo = lo * 256 + (bytes[15 - i] as Field);
        hi = hi * 256 + (bytes[31 - i] as Field);
    }
    let s_lt_l = (bytes[31] < 16) | ((hi == L_HI) & ((lo as u128) < L_LO));
    (lo + hi * TWO_POW_128, s_lt_l)
}

/// Encode an Ed25519 point into its 32-byte compressed form (RFC 8032 5.1.2):
/// the little-endian y-coordinate with the low bit of x stored in the most
/// significant bit. Valid points have y < 2^255, so that bit is always free.
pub fn compress(point: Ed25519) -> [u8; 32] {
    let mut enc: [u8; 32] = point.y.to_le_bytes();
    let x_bytes: [u8; 32] = point.x.to_le_bytes();
    let x_sign = x_bytes[0] & 1;
    enc[31] = enc[31] | (x_sign << 7);
    enc
}

/// Reduce a 64-byte little-endian integer (the SHA-512 digest) modulo the
/// Ed25519 group order, returning it as a curve scalar.
///
/// Uses Horner's method over 32-bit words in the scalar field Fr
/// so the wide value is reduced as it is accumulated.
fn reduce_wide(bytes: [u8; 64]) -> ScalarField<64> {
    let base = Fr::from_limbs([0x100000000, 0, 0]); // 2^32
    let mut acc = Fr::zero();
    for i in 0..16 {
        let j = 15 - i; // most-significant 32-bit word first
        let word = (bytes[4 * j] as u128)
            + (bytes[4 * j + 1] as u128) * 0x100
            + (bytes[4 * j + 2] as u128) * 0x10000
            + (bytes[4 * j + 3] as u128) * 0x1000000;
        acc = acc * base + Fr::from_limbs([word, 0, 0]);
    }

    // acc is reduced mod ell (< 2^253), so it fits in a single field element.
    let limbs = acc.get_limbs();
    let p120: Field = 0x1000000000000000000000000000000; // 2^120
    let k_field =
        limbs[0] as Field + (limbs[1] as Field) * p120 + (limbs[2] as Field) * p120 * p120;
    ScalarField::<64>::from(k_field)
}

mod test;
mod benchmarks;
