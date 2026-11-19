import 'dart:convert';
import 'dart:io';

import 'package:rapid_crypto/rapid_crypto.dart';

Future<void> main(List<String> args) async {
  // One-shot hashing, exactly like package:crypto.
  final digest = sha256.convert(utf8.encode('hello'));
  print('sha256("hello") = $digest');

  // HMAC.
  final mac = Hmac(sha256, utf8.encode('secret')).convert(utf8.encode('message'));
  print('HMAC-SHA256 = $mac');

  // Streaming: hash a file without loading it into memory.
  if (args.isNotEmpty) {
    final fileDigest = await sha256.bind(File(args.first).openRead()).first;
    print('sha256(${args.first}) = $fileDigest');
  }

  print('Native: $rapidCryptoIsNative, CPU features: $rapidCryptoCpuFeatures');
}
