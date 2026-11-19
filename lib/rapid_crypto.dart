/// package:crypto, faster.
///
/// Import this instead of `package:crypto/crypto.dart`. The API is the same:
/// `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha512224`,
/// `sha512256` and `Hmac` are replaced by versions computed in Rust, and
/// `Digest` and `Hash` are package:crypto's own classes, so results and types
/// stay compatible.
///
/// ```dart
/// import 'package:rapid_crypto/rapid_crypto.dart';
///
/// final digest = sha256.convert(utf8.encode('hello'));
/// final mac = Hmac(sha256, key).convert(message);
/// ```
///
/// On CPUs with SHA instructions (Apple silicon and iPhones, modern Android,
/// x86 with SHA-NI), SHA-1 and SHA-256 are about 12x faster than
/// package:crypto, and SHA-512 about 5x. On the web, rapid_crypto uses
/// package:crypto's pure-Dart code.
library;

export 'package:crypto/crypto.dart'
    hide
        md5,
        sha1,
        sha224,
        sha256,
        sha384,
        sha512,
        sha512224,
        sha512256,
        Hmac;

export 'src/hashes_web.dart'
    if (dart.library.ffi) 'src/hashes_native.dart';
