// FFI binding to the Rust library (native/src/lib.rs), bundled by
// hook/build.dart under this library's asset id.
//
// Inputs go to Rust as `Uint8List.address` through leaf calls, so nothing is
// copied. `.address` is only allowed directly as an argument of a leaf call,
// which is why the small wrappers below live in this file.

import 'dart:ffi';
import 'dart:typed_data';

@Native<Int32 Function(Int32, Pointer<Uint8>, Size, Pointer<Uint8>)>(
    isLeaf: true)
external int rc_digest(int algo, Pointer<Uint8> data, int len, Pointer<Uint8> out);

@Native<
        Int32 Function(
            Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>)>(
    isLeaf: true)
external int rc_hmac(int algo, Pointer<Uint8> key, int keyLen,
    Pointer<Uint8> data, int len, Pointer<Uint8> out);

@Native<Pointer<Void> Function(Int32)>(isLeaf: true)
external Pointer<Void> rc_hasher_new(int algo);

@Native<Void Function(Pointer<Void>, Pointer<Uint8>, Size)>(isLeaf: true)
external void rc_hasher_update(Pointer<Void> h, Pointer<Uint8> data, int len);

@Native<Int32 Function(Pointer<Void>, Pointer<Uint8>)>(isLeaf: true)
external int rc_hasher_finish(Pointer<Void> h, Pointer<Uint8> out);

@Native<Void Function(Pointer<Void>)>(isLeaf: true)
external void rc_hasher_free(Pointer<Void> h);

@Native<Int32 Function()>(isLeaf: true)
external int rc_cpu_features();

/// Frees streaming hashers that are dropped without being closed.
final hasherFinalizer =
    NativeFinalizer(Native.addressOf<NativeFunction<Void Function(Pointer<Void>)>>(
            rc_hasher_free)
        .cast());

/// Digest output buffer (64 bytes fits every algorithm). One per isolate;
/// each call copies the result out before returning.
final Uint8List _out = Uint8List(64);

Uint8List _result(int n) {
  if (n < 0) throw StateError('rapid_crypto: unknown algorithm');
  return _out.sublist(0, n);
}

/// One-shot digest of [data] with algorithm [algo].
Uint8List nativeDigest(int algo, Uint8List data) =>
    _result(rc_digest(algo, data.address, data.length, _out.address));

/// One-shot HMAC of [data] under [key] with algorithm [algo].
Uint8List nativeHmac(int algo, Uint8List key, Uint8List data) => _result(
    rc_hmac(algo, key.address, key.length, data.address, data.length,
        _out.address));

/// Feeds [data] to the streaming hasher [h].
void nativeUpdate(Pointer<Void> h, Uint8List data) {
  if (data.isEmpty) return;
  rc_hasher_update(h, data.address, data.length);
}

/// Finishes (and frees) the streaming hasher [h].
Uint8List nativeFinish(Pointer<Void> h) =>
    _result(rc_hasher_finish(h, _out.address));

/// Hardware hash instructions on this CPU: bit 0 = SHA-1/SHA-256,
/// bit 1 = SHA-512.
int nativeCpuFeatures() => rc_cpu_features();
