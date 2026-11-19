//! Rust core for rapid_crypto: MD5, SHA-1, SHA-2 and HMAC behind a small C ABI.
//!
//! Every function takes an algorithm id:
//!
//! | id | algorithm   | digest bytes | block bytes |
//! |----|-------------|--------------|-------------|
//! | 0  | MD5         | 16           | 64          |
//! | 1  | SHA-1       | 20           | 64          |
//! | 2  | SHA-224     | 28           | 64          |
//! | 3  | SHA-256     | 32           | 64          |
//! | 4  | SHA-384     | 48           | 128         |
//! | 5  | SHA-512     | 64           | 128         |
//! | 6  | SHA-512/224 | 28           | 128         |
//! | 7  | SHA-512/256 | 32           | 128         |
//!
//! Output buffers must hold at least 64 bytes. Functions that write a digest
//! return its length, or -1 for an unknown algorithm id.
//!
//! Inputs are read in place (Dart passes `Uint8List.address` through leaf
//! calls), so nothing is copied across the boundary.

use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

/// Largest digest any algorithm produces (SHA-512).
pub const MAX_DIGEST: usize = 64;

/// A streaming hasher for any supported algorithm.
pub enum Hasher {
    Md5(Md5),
    Sha1(Sha1),
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Sha512_224(Sha512_224),
    Sha512_256(Sha512_256),
}

/// Runs `$body` with `$t` bound to the hash type for algorithm `$algo`,
/// or evaluates to -1 for an unknown id.
macro_rules! with_algo {
    ($algo:expr, $t:ident => $body:expr) => {
        match $algo {
            0 => { type $t = Md5; $body }
            1 => { type $t = Sha1; $body }
            2 => { type $t = Sha224; $body }
            3 => { type $t = Sha256; $body }
            4 => { type $t = Sha384; $body }
            5 => { type $t = Sha512; $body }
            6 => { type $t = Sha512_224; $body }
            7 => { type $t = Sha512_256; $body }
            _ => -1,
        }
    };
}

impl Hasher {
    pub fn new(algo: i32) -> Option<Self> {
        Some(match algo {
            0 => Self::Md5(Md5::new()),
            1 => Self::Sha1(Sha1::new()),
            2 => Self::Sha224(Sha224::new()),
            3 => Self::Sha256(Sha256::new()),
            4 => Self::Sha384(Sha384::new()),
            5 => Self::Sha512(Sha512::new()),
            6 => Self::Sha512_224(Sha512_224::new()),
            7 => Self::Sha512_256(Sha512_256::new()),
            _ => return None,
        })
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Md5(h) => h.update(data),
            Self::Sha1(h) => h.update(data),
            Self::Sha224(h) => h.update(data),
            Self::Sha256(h) => h.update(data),
            Self::Sha384(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
            Self::Sha512_224(h) => h.update(data),
            Self::Sha512_256(h) => h.update(data),
        }
    }

    /// Writes the digest to `out` and returns its length.
    pub fn finish(self, out: &mut [u8]) -> usize {
        fn put(d: &[u8], out: &mut [u8]) -> usize {
            out[..d.len()].copy_from_slice(d);
            d.len()
        }
        match self {
            Self::Md5(h) => put(&h.finalize(), out),
            Self::Sha1(h) => put(&h.finalize(), out),
            Self::Sha224(h) => put(&h.finalize(), out),
            Self::Sha256(h) => put(&h.finalize(), out),
            Self::Sha384(h) => put(&h.finalize(), out),
            Self::Sha512(h) => put(&h.finalize(), out),
            Self::Sha512_224(h) => put(&h.finalize(), out),
            Self::Sha512_256(h) => put(&h.finalize(), out),
        }
    }
}

/// One-shot digest of `data`. Returns the digest length, or -1.
pub fn digest(algo: i32, data: &[u8], out: &mut [u8]) -> i32 {
    with_algo!(algo, H => {
        let d = H::digest(data);
        out[..d.len()].copy_from_slice(&d);
        d.len() as i32
    })
}

/// One-shot HMAC of `data` under `key` (any length). Returns the length, or -1.
pub fn hmac(algo: i32, key: &[u8], data: &[u8], out: &mut [u8]) -> i32 {
    with_algo!(algo, H => {
        // HMAC accepts keys of any length, so this cannot fail.
        let mut mac = <Hmac<H> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(data);
        let d = mac.finalize().into_bytes();
        out[..d.len()].copy_from_slice(&d);
        d.len() as i32
    })
}

// ---------------------------------------------------------------------------
// C ABI

unsafe fn slice<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if len == 0 || p.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(p, len) }
    }
}

unsafe fn out_buf<'a>(p: *mut u8) -> &'a mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(p, MAX_DIGEST) }
}

/// One-shot digest. `out` must hold 64 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_digest(algo: i32, data: *const u8, len: usize, out: *mut u8) -> i32 {
    unsafe { digest(algo, slice(data, len), out_buf(out)) }
}

/// One-shot HMAC. `out` must hold 64 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_hmac(
    algo: i32,
    key: *const u8,
    key_len: usize,
    data: *const u8,
    len: usize,
    out: *mut u8,
) -> i32 {
    unsafe { hmac(algo, slice(key, key_len), slice(data, len), out_buf(out)) }
}

/// Starts a streaming hash. Returns null for an unknown algorithm. Free it
/// with `rc_hasher_finish` (which consumes it) or `rc_hasher_free`.
#[unsafe(no_mangle)]
pub extern "C" fn rc_hasher_new(algo: i32) -> *mut Hasher {
    match Hasher::new(algo) {
        Some(h) => Box::into_raw(Box::new(h)),
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_hasher_update(h: *mut Hasher, data: *const u8, len: usize) {
    if let Some(h) = unsafe { h.as_mut() } {
        h.update(unsafe { slice(data, len) });
    }
}

/// Finishes and frees the hasher, writing the digest to `out` (64 bytes).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_hasher_finish(h: *mut Hasher, out: *mut u8) -> i32 {
    if h.is_null() {
        return -1;
    }
    let h = unsafe { Box::from_raw(h) };
    h.finish(unsafe { out_buf(out) }) as i32
}

/// Frees a hasher that was never finished (used by Dart's NativeFinalizer).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_hasher_free(h: *mut Hasher) {
    if !h.is_null() {
        drop(unsafe { Box::from_raw(h) });
    }
}

/// Which hardware hash instructions this CPU has, as bit flags:
/// 1 = SHA-1/SHA-256, 2 = SHA-512. Informational (the hash crates check
/// on their own); used by tests and benchmarks.
#[unsafe(no_mangle)]
pub extern "C" fn rc_cpu_features() -> i32 {
    #[allow(unused_mut)]
    let mut f = 0;
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("sha2") {
            f |= 1;
        }
        if std::arch::is_aarch64_feature_detected!("sha3") {
            f |= 2;
        }
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if std::is_x86_feature_detected!("sha") {
            f |= 1;
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_digest(algo: i32, data: &[u8]) -> String {
        let mut out = [0u8; MAX_DIGEST];
        let n = digest(algo, data, &mut out) as usize;
        hex::encode(&out[..n])
    }

    // FIPS 180-4 / RFC 1321 test vectors for "abc".
    #[test]
    fn abc_vectors() {
        let cases = [
            (0, "900150983cd24fb0d6963f7d28e17f72"),
            (1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (2, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
            (3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (4, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
            (5, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
            (6, "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"),
            (7, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"),
        ];
        for (algo, want) in cases {
            assert_eq!(hex_digest(algo, b"abc"), want, "algo {algo}");
        }
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i * 31 % 251) as u8).collect();
        for algo in 0..8 {
            let mut h = Hasher::new(algo).unwrap();
            for chunk in data.chunks(997) {
                h.update(chunk);
            }
            let mut out = [0u8; MAX_DIGEST];
            let n = h.finish(&mut out);
            assert_eq!(hex::encode(&out[..n]), hex_digest(algo, &data), "algo {algo}");
        }
    }

    // RFC 4231 test case 2.
    #[test]
    fn hmac_sha256_rfc4231() {
        let mut out = [0u8; MAX_DIGEST];
        let n = hmac(3, b"Jefe", b"what do ya want for nothing?", &mut out) as usize;
        assert_eq!(
            hex::encode(&out[..n]),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn unknown_algorithm() {
        let mut out = [0u8; MAX_DIGEST];
        assert_eq!(digest(99, b"", &mut out), -1);
        assert_eq!(hmac(99, b"", b"", &mut out), -1);
        assert!(Hasher::new(99).is_none());
    }
}
