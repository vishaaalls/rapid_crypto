## 0.1.0

- Initial release: drop-in replacement for package:crypto.
- `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha512224`,
  `sha512256` and `Hmac` computed in Rust (RustCrypto), using the CPU's
  SHA-1/SHA-256 and SHA-512 instructions when available.
- Chunked conversion through a native streaming hasher.
- Web falls back to package:crypto's pure-Dart code.
- package:crypto's full test suite runs against rapid_crypto.
