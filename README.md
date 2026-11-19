# rapid_crypto

**package:crypto, faster.** A drop-in replacement that computes MD5, SHA-1,
SHA-2 and HMAC in Rust, using the CPU's SHA instructions when they're
available. Swap the import and keep your code:

```diff
- import 'package:crypto/crypto.dart';
+ import 'package:rapid_crypto/rapid_crypto.dart';
```

```dart
final digest = sha256.convert(utf8.encode('hello'));
final mac = Hmac(sha256, key).convert(message);
```

## Speed

iPhone 16 Pro, Flutter release build:

| | package:crypto | rapid_crypto | Speedup |
|---|---|---|---|
| SHA-256, 64 B | 0.76 µs | 0.05 µs | **15x** |
| SHA-256, 1 MB | 4.90 ms | 0.41 ms | **12x** |
| SHA-256, 100 MB file (streamed) | 498 ms | 42 ms | **12x** |
| SHA-1, 1 MB | 4.49 ms | 0.37 ms | **12x** |
| SHA-512, 1 MB | 3.34 ms | 0.60 ms | **5.6x** |
| MD5, 1 MB | 2.22 ms | 1.28 ms | 1.7x |
| HMAC-SHA256, 64 B | 1.95 µs | 0.13 µs | **15x** |

The Apple M4 Mac numbers are about the same (`bench/bin/bench.dart`).

**Where the speed comes from:**
- **SHA-1 and SHA-256** use the CPU's SHA instructions: ARMv8 on iPhones,
  Apple silicon and nearly all Android phones, and SHA-NI on recent x86.
- **SHA-512** uses ARMv8.2 SHA-512 instructions where present. That's Apple
  chips and recent Android flagships, but not every Android phone.
- **MD5** has no CPU instructions, so its gain is just native code vs Dart.

The Rust code checks the CPU at runtime and falls back to software, so it
works on every device.

## Same API, same results

- `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha512224` and
  `sha512256` are `const Hash` values, just like in package:crypto.
- `Digest` and `Hash` are package:crypto's own classes, re-exported, so types
  stay compatible with code and packages that use package:crypto.
- `Hmac` is a subclass of package:crypto's `Hmac`. With a rapid_crypto hash it
  computes the whole HMAC in one native call. With any other `Hash`, it uses
  package:crypto's implementation.
- Chunked conversion (`startChunkedConversion`, `bind` on streams) uses a
  native streaming hasher, so hashing a large file never loads it into
  memory.
- Errors behave the same: `add` after `close` throws `StateError`, and
  `addSlice` validates its range.

**Tested against package:crypto:** its full test suite runs unchanged against
rapid_crypto (`test/crypto_suite/`), including the Wycheproof HMAC vectors.
The interop tests (`test/interop_test.dart`) compare every algorithm with
package:crypto at block-boundary sizes, with random chunking, many input list
types, and HMAC keys shorter than, equal to and longer than the block size.

## Platforms

| Platform | How it runs |
|---|---|
| Android, iOS, macOS, Linux, Windows | Rust, through `dart:ffi` |
| Web | package:crypto's pure-Dart code (same results) |

On the web, WebAssembly has no SHA instructions, so a Rust/WASM build would
gain little. rapid_crypto falls back to package:crypto there, so the same
code works everywhere. `rapidCryptoIsNative` tells you which path is active,
and `rapidCryptoCpuFeatures` reports which SHA instructions the CPU has.

## Installing

```yaml
dependencies:
  rapid_crypto: ^0.1.1
```

The native library is built by a Dart build hook (`hook/build.dart`), so
there's no Flutter plugin setup. Released versions download a prebuilt,
SHA-256-verified binary for 12 platforms from GitHub Releases, so you don't
need Rust. Without a prebuilt binary for your target, the hook builds with
cargo. That needs [Rust](https://rustup.rs) and
`rustup target add <triple>`.

To force a source build:

```yaml
hooks:
  user_defines:
    rapid_crypto:
      from_source: true
```

## Development

```bash
dart test -p vm         # package:crypto's suite + interop tests (builds the Rust code)
dart test -p chrome     # web fallback
cd native && cargo test --release
dart build cli -t bench/bin/bench.dart && ./build/cli/*/bundle/bin/bench
```

Releasing: push a tag like `v0.1.1`. `.github/workflows/release.yml` builds
the 12 platform binaries and attaches them with `SHA256SUMS`. Then run
`dart run tool/update_prebuilt.dart v0.1.1` and commit
`lib/src/prebuilt.dart`.

## Part of the rapid_* family

- [rapid_image](https://pub.dev/packages/rapid_image): package:image, faster
- [rapid_archive](https://pub.dev/packages/rapid_archive): package:archive, faster
- **rapid_crypto**: package:crypto, faster
