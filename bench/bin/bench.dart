// rapid_crypto vs package:crypto.
//
// For release-like numbers, run it AOT-compiled (JIT makes Dart look slower):
//   dart build cli -t bench/bin/bench.dart
//   ./build/cli/<platform>/bundle/bin/bench
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:rapid_crypto/rapid_crypto.dart' as rapid;

double _timeIt(void Function() f, {int minMicros = 250000, int runs = 5}) {
  final sw = Stopwatch()..start();
  var warm = 0;
  while (sw.elapsedMicroseconds < 100000) {
    f();
    warm++;
  }
  final perCall = sw.elapsedMicroseconds / warm;
  final iters = max(1, (minMicros / max(perCall, 0.001)).ceil());
  final samples = <double>[];
  for (var r = 0; r < runs; r++) {
    final s = Stopwatch()..start();
    for (var i = 0; i < iters; i++) {
      f();
    }
    samples.add(s.elapsedMicroseconds / iters);
  }
  samples.sort();
  return samples[runs ~/ 2];
}

String _fmt(double us) => us < 1000
    ? '${us.toStringAsFixed(2)} µs'
    : '${(us / 1000).toStringAsFixed(2)} ms';

String _size(int n) => n >= 1 << 20
    ? '${n >> 20} MB'
    : n >= 1024
        ? '${n >> 10} KB'
        : '$n B';

void main() {
  final f = rapid.rapidCryptoCpuFeatures;
  print('CPU SHA-1/SHA-256 instructions: ${f.sha256}, '
      'SHA-512 instructions: ${f.sha512}');
  print('Build: ${const bool.fromEnvironment('dart.vm.product') ? 'AOT' : 'JIT (Dart numbers are pessimistic)'}');

  final rnd = Random(42);
  Uint8List bytes(int n) =>
      Uint8List.fromList(List.generate(n, (_) => rnd.nextInt(256)));
  final pairs = {
    'MD5': (crypto.md5, rapid.md5),
    'SHA-1': (crypto.sha1, rapid.sha1),
    'SHA-256': (crypto.sha256, rapid.sha256),
    'SHA-512': (crypto.sha512, rapid.sha512),
  };
  final key = bytes(32);
  for (final MapEntry(key: name, value: (ref, fast)) in pairs.entries) {
    print('\n$name            package:crypto   rapid_crypto   speedup');
    for (final n in [64, 1024, 1 << 20, 16 << 20]) {
      final d = bytes(n);
      final a = _timeIt(() => ref.convert(d), runs: n > 1 << 20 ? 3 : 5);
      final b = _timeIt(() => fast.convert(d), runs: n > 1 << 20 ? 3 : 5);
      print('  ${_size(n).padRight(14)} ${_fmt(a).padLeft(12)} '
          '${_fmt(b).padLeft(14)} ${(a / b).toStringAsFixed(1).padLeft(8)}x');
    }
    final d = bytes(64);
    final a = _timeIt(() => crypto.Hmac(ref, key).convert(d));
    final b = _timeIt(() => rapid.Hmac(fast, key).convert(d));
    print('  ${'HMAC 64 B'.padRight(14)} ${_fmt(a).padLeft(12)} '
        '${_fmt(b).padLeft(14)} ${(a / b).toStringAsFixed(1).padLeft(8)}x');
  }
}
