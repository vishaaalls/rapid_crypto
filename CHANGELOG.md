## 0.1.1

- First published release.
- Apple (macOS/iOS) libraries are linked with spare header space, so Dart's
  and Flutter's bundlers can rewrite their install names under long paths.

## 0.1.0

- Initial version (not published): drop-in replacement for package:crypto.
- `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha512224`,
  `sha512256` and `Hmac` computed in Rust (RustCrypto), using the CPU's
  SHA-1/SHA-256 and SHA-512 instructions when available.
- Chunked conversion through a native streaming hasher.
- Web falls back to package:crypto's pure-Dart code.
- package:crypto's full test suite runs against rapid_crypto.
