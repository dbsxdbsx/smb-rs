use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::CryptoError;

type HmacSha256 = Hmac<Sha256>;

/// SMB 3.x session keys are 16 bytes (AES-128).
pub type DerivedKey = [u8; 16];
pub type KeyToDerive = [u8; 16];

/// NIST SP 800-108 counter-mode KDF, the profile MS-SMB2 uses.
///
/// `r = 32` (the counter is a 4-byte big-endian integer), HMAC-SHA256, a
/// separator `0x00` between label and context, and `L` (output length in
/// bits) appended as a big-endian `u32`.
///
/// This used to call `kbkdf` 0.1.0-rc.1. Its length guard is
/// `2usize.pow(32) - 1`. On a 32-bit `usize` (Android `armeabi-v7a` debug)
/// that exponentiation panics, so SMB 3 session setup never finishes.
/// A 16-byte key is one HMAC-SHA256 block, so there is no multi-round
/// counter and no power-of-two bound to compute.
pub fn kbkdf_hmacsha256(
    key: &KeyToDerive,
    label: &[u8],
    context: &[u8],
) -> Result<DerivedKey, CryptoError> {
    const OUT_BITS: u32 = 128;
    let mut mac = HmacSha256::new_from_slice(key)?;
    // r = 32: counter i = 1 as four big-endian bytes.
    mac.update(&1u32.to_be_bytes());
    mac.update(label);
    mac.update(&[0]);
    mac.update(context);
    mac.update(&OUT_BITS.to_be_bytes());
    let block = mac.finalize().into_bytes();
    let mut output = [0u8; 16];
    output.copy_from_slice(&block[..16]);
    Ok(output)
}

#[cfg(test)]
mod tests {
    #[test]
    fn r32_bound_does_not_need_a_32bit_usize_pow() {
        // `2u32.pow(32)` is the expression that panics on armeabi-v7a debug.
        assert!(u32::checked_pow(2, 32).is_none());
        assert_eq!((1u64 << 32) - 1, u64::from(u32::MAX));
    }
}
