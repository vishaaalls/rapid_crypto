// Compares rapid_crypto with package:crypto directly: same digests for every
// algorithm, input size, input type and chunking pattern.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:rapid_crypto/rapid_crypto.dart' as rapid;
import 'package:test/test.dart';

final _pairs = <String, (crypto.Hash, crypto.Hash)>{
  'md5': (crypto.md5, rapid.md5),
  'sha1': (crypto.sha1, rapid.sha1),
  'sha224': (crypto.sha224, rapid.sha224),
  'sha256': (crypto.sha256, rapid.sha256),
  'sha384': (crypto.sha384, rapid.sha384),
  'sha512': (crypto.sha512, rapid.sha512),
  'sha512224': (crypto.sha512224, rapid.sha512224),
  'sha512256': (crypto.sha512256, rapid.sha512256),
};

// Around the 64- and 128-byte block sizes and their padding boundaries.
const _sizes = [
  0, 1, 3, 55, 56, 57, 63, 64, 65, 111, 112, 113, 127, 128, 129, //
  1000, 4096, 100003, 1 << 20,
];

Uint8List _random(Random r, int n) =>
    Uint8List.fromList(List.generate(n, (_) => r.nextInt(256)));

/// Feeds [data] to a chunked conversion in random-sized pieces, mixing
/// add and addSlice.
crypto.Digest _chunked(crypto.Hash h, Uint8List data, Random r) {
  late crypto.Digest out;
  final sink = h.startChunkedConversion(_Capture((d) => out = d));
  var i = 0;
  while (i < data.length) {
    final n = min(data.length - i, r.nextInt(300) + 1);
    if (r.nextBool()) {
      sink.add(Uint8List.sublistView(data, i, i + n));
    } else {
      sink.addSlice(data, i, i + n, false);
    }
    i += n;
  }
  sink.close();
  return out;
}

class _Capture implements Sink<crypto.Digest> {
  _Capture(this.onDigest);
  final void Function(crypto.Digest) onDigest;
  @override
  void add(crypto.Digest d) => onDigest(d);
  @override
  void close() {}
}

void main() {
  test('runs natively on the VM', () {
    expect(rapid.rapidCryptoIsNative, isTrue);
    expect(rapid.sha256, isNot(same(crypto.sha256)));
  });

  for (final MapEntry(key: name, value: (ref, fast)) in _pairs.entries) {
    group(name, () {
      test('blockSize matches', () {
        expect(fast.blockSize, ref.blockSize);
      });

      test('one-shot matches at every size', () {
        final r = Random(1);
        for (final n in _sizes) {
          final d = _random(r, n);
          expect(fast.convert(d), ref.convert(d), reason: '$n bytes');
        }
      });

      test('chunked matches one-shot', () {
        final r = Random(2);
        for (final n in _sizes) {
          final d = _random(r, n);
          expect(_chunked(fast, d, r), ref.convert(d), reason: '$n bytes');
        }
      });

      test('accepts any List<int>', () {
        final r = Random(3);
        final bytes = _random(r, 777);
        final want = ref.convert(bytes);
        expect(fast.convert(bytes.toList()), want, reason: 'growable List');
        expect(fast.convert(List<int>.unmodifiable(bytes)), want,
            reason: 'unmodifiable List');
        expect(fast.convert(bytes.asUnmodifiableView()), want,
            reason: 'unmodifiable Uint8List view');
        expect(fast.convert(Uint8List.sublistView(bytes, 0, 777)), want,
            reason: 'Uint8List view');
        // Values outside 0-255 keep their low 8 bits, like package:crypto.
        final wide = [for (final b in bytes) b + 256 * 3];
        expect(fast.convert(wide), ref.convert(wide), reason: 'wide ints');
      });

      test('addSlice on unmodifiable and plain lists', () {
        final r = Random(4);
        final bytes = _random(r, 500);
        for (final List<int> input in [
          bytes.asUnmodifiableView(),
          bytes.toList(),
        ]) {
          late crypto.Digest out;
          fast.startChunkedConversion(_Capture((d) => out = d))
            ..addSlice(input, 0, 200, false)
            ..addSlice(input, 200, 500, true);
          expect(out, ref.convert(bytes));
        }
      });

      test('HMAC matches for short, block-sized and long keys', () {
        final r = Random(5);
        for (final keyLen in [0, 1, 20, ref.blockSize, ref.blockSize + 1, 300]) {
          final key = _random(r, keyLen);
          for (final n in [0, 1, 64, 1000, 100003]) {
            final d = _random(r, n);
            final want = crypto.Hmac(ref, key).convert(d);
            expect(rapid.Hmac(fast, key).convert(d), want,
                reason: 'key $keyLen, data $n');
            // Chunked HMAC streams through the native hash.
            late crypto.Digest out;
            rapid.Hmac(fast, key).startChunkedConversion(_Capture((x) => out = x))
              ..add(d)
              ..close();
            expect(out, want, reason: 'chunked, key $keyLen, data $n');
          }
        }
      });
    });
  }

  test('Hmac is a package:crypto Hmac and works with any Hash', () {
    final key = utf8.encode('key');
    final msg = utf8.encode('The quick brown fox jumps over the lazy dog');
    final mac = rapid.Hmac(rapid.sha256, key);
    expect(mac, isA<crypto.Hmac>());
    // A package:crypto hash goes through package:crypto's implementation.
    expect(rapid.Hmac(crypto.sha256, key).convert(msg),
        crypto.Hmac(crypto.sha256, key).convert(msg));
    expect(mac.convert(msg).toString(),
        'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8');
  });

  test('hashes are compile-time constants', () {
    const crypto.Hash h = rapid.sha256;
    expect(h.convert(utf8.encode('abc')).toString(),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  test('add after close throws like package:crypto', () {
    final sink = rapid.sha256.startChunkedConversion(_Capture((_) {}))..close();
    expect(() => sink.add([1]), throwsStateError);
    expect(() => sink.addSlice([1], 0, 1, false), throwsStateError);
    sink.close(); // closing twice is fine
  });

  test('addSlice validates its range', () {
    final sink = rapid.sha256.startChunkedConversion(_Capture((_) {}));
    expect(() => sink.addSlice([1, 2, 3], 2, 1, false), throwsRangeError);
    expect(() => sink.addSlice([1, 2, 3], 0, 4, false), throwsRangeError);
  });

  test('unclosed chunked conversions are freed by the finalizer', () {
    // Leaks would show up under a memory checker; here we only make sure
    // abandoning many sinks does not crash.
    for (var i = 0; i < 10000; i++) {
      rapid.sha512.startChunkedConversion(_Capture((_) {})).add([i & 0xff]);
    }
  });

  test('reports CPU features', () {
    final f = rapid.rapidCryptoCpuFeatures;
    expect(f.sha256, isA<bool>());
    expect(f.sha512, isA<bool>());
  });
}
