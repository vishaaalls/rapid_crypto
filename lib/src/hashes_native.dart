// Native (dart:ffi) implementations of package:crypto's hashes and Hmac.

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:crypto/crypto.dart' show Digest, Hash;

import 'native_ffi.dart';

/// An implementation of the [MD5][rfc] hash function, computed in Rust.
///
/// **Warning**: MD5 has known collisions and should only be used when
/// required for backwards compatibility.
///
/// [rfc]: https://tools.ietf.org/html/rfc1321
const Hash md5 = _RapidHash._(0, 'MD5', 64);

/// An implementation of the [SHA-1][rfc] hash function, computed in Rust.
///
/// [rfc]: http://tools.ietf.org/html/rfc3174
const Hash sha1 = _RapidHash._(1, 'SHA-1', 64);

/// An implementation of the [SHA-224][rfc] hash function, computed in Rust.
///
/// [rfc]: http://tools.ietf.org/html/rfc6234
const Hash sha224 = _RapidHash._(2, 'SHA-224', 64);

/// An implementation of the [SHA-256][rfc] hash function, computed in Rust.
///
/// [rfc]: http://tools.ietf.org/html/rfc6234
const Hash sha256 = _RapidHash._(3, 'SHA-256', 64);

/// An implementation of the [SHA-384][rfc] hash function, computed in Rust.
///
/// [rfc]: http://tools.ietf.org/html/rfc6234
const Hash sha384 = _RapidHash._(4, 'SHA-384', 128);

/// An implementation of the [SHA-512][rfc] hash function, computed in Rust.
///
/// [rfc]: http://tools.ietf.org/html/rfc6234
const Hash sha512 = _RapidHash._(5, 'SHA-512', 128);

/// An implementation of the [SHA-512/224][FIPS] hash function, computed in
/// Rust.
///
/// [FIPS]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
const Hash sha512224 = _RapidHash._(6, 'SHA-512/224', 128);

/// An implementation of the [SHA-512/256][FIPS] hash function, computed in
/// Rust.
///
/// [FIPS]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
const Hash sha512256 = _RapidHash._(7, 'SHA-512/256', 128);

/// Whether hashes are computed natively on this platform (false on the web,
/// where rapid_crypto uses package:crypto's pure-Dart code).
const bool rapidCryptoIsNative = true;

/// Hardware hash instructions the CPU offers: `sha256` covers SHA-1, SHA-224
/// and SHA-256; `sha512` covers SHA-384, SHA-512 and the SHA-512/t variants.
/// Without them the Rust code uses a software implementation (still faster
/// than pure Dart, by less).
({bool sha256, bool sha512}) get rapidCryptoCpuFeatures {
  final f = nativeCpuFeatures();
  return (sha256: f & 1 != 0, sha512: f & 2 != 0);
}

/// Converts [input] to bytes Rust can read in place. Lists that aren't
/// already a modifiable [Uint8List] are copied; values outside 0-255 keep
/// their low 8 bits, as in package:crypto.
Uint8List _bytes(List<int> input) {
  if (input is Uint8List && !_isUnmodifiableView(input)) return input;
  return Uint8List.fromList(input);
}

// `Uint8List.address` is not available for unmodifiable views.
final _unmodifiableType = Uint8List(0).asUnmodifiableView().runtimeType;
bool _isUnmodifiableView(Uint8List l) => l.runtimeType == _unmodifiableType;

/// A [Hash] computed by the Rust library. Behaves exactly like the
/// package:crypto hash of the same name.
final class _RapidHash extends Hash {
  const _RapidHash._(this._algo, this._name, this.blockSize);

  final int _algo;
  final String _name;

  @override
  final int blockSize;

  @override
  Digest convert(List<int> input) =>
      Digest(nativeDigest(_algo, _bytes(input)));

  @override
  ByteConversionSink startChunkedConversion(Sink<Digest> sink) =>
      _RapidHashSink(_algo, sink);

  @override
  String toString() => _name;
}

/// Streaming hash backed by a native hasher. One FFI call per chunk.
class _RapidHashSink extends ByteConversionSink implements Finalizable {
  _RapidHashSink(int algo, this._sink) : _h = rc_hasher_new(algo) {
    if (_h == nullptr) throw StateError('rapid_crypto: unknown algorithm');
    hasherFinalizer.attach(this, _h, detach: this);
  }

  final Sink<Digest> _sink;
  final Pointer<Void> _h;
  bool _isClosed = false;

  @override
  void add(List<int> chunk) {
    if (_isClosed) throw StateError('Hash.add() called after close().');
    nativeUpdate(_h, _bytes(chunk));
  }

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    if (_isClosed) throw StateError('Hash.addSlice() called after close().');
    RangeError.checkValidRange(start, end, chunk.length);
    if (start < end) {
      nativeUpdate(
          _h,
          chunk is Uint8List && !_isUnmodifiableView(chunk)
              ? Uint8List.sublistView(chunk, start, end)
              : Uint8List.fromList(chunk.sublist(start, end)));
    }
    if (isLast) close();
  }

  @override
  void close() {
    if (_isClosed) return;
    _isClosed = true;
    hasherFinalizer.detach(this);
    _sink.add(Digest(nativeFinish(_h)));
    _sink.close();
  }
}

/// An implementation of [keyed-hash method authentication codes][rfc].
///
/// Same API and results as package:crypto's `Hmac` (and a subtype of it).
/// With a rapid_crypto hash, [convert] computes the whole HMAC in one native
/// call; chunked conversion streams through the native hash.
///
/// [rfc]: https://tools.ietf.org/html/rfc2104
class Hmac extends crypto.Hmac {
  /// Create an [Hmac] object from a [Hash] and a binary key.
  ///
  /// The key should be a secret shared between the sender and receiver of the
  /// message.
  Hmac(Hash hash, List<int> key)
      : _algo = hash is _RapidHash ? hash._algo : null,
        _key = Uint8List.fromList(key),
        super(hash, key);

  final int? _algo;
  final Uint8List _key;

  @override
  Digest convert(List<int> input) {
    final algo = _algo;
    if (algo == null) return super.convert(input);
    return Digest(nativeHmac(algo, _key, _bytes(input)));
  }
}
