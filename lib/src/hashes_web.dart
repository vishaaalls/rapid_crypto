// Web: no native code. rapid_crypto uses package:crypto's pure-Dart hashes,
// so code that imports rapid_crypto still compiles and gives the same results.
//
// (WebAssembly has no SHA instructions, so a Rust/WASM build would gain
// little over package:crypto here.)

export 'package:crypto/crypto.dart'
    show
        md5,
        sha1,
        sha224,
        sha256,
        sha384,
        sha512,
        sha512224,
        sha512256,
        Hmac;

/// Whether hashes are computed natively on this platform (false on the web,
/// where rapid_crypto uses package:crypto's pure-Dart code).
const bool rapidCryptoIsNative = false;

/// Hardware hash instructions in use: none on the web.
({bool sha256, bool sha512}) get rapidCryptoCpuFeatures =>
    (sha256: false, sha512: false);
