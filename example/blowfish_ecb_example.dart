import 'dart:convert';
import 'dart:typed_data';

import 'package:blowfish_ecb/blowfish_ecb.dart';

void main() {
  const key = 'Passw0rd!';
  const message = 'Hello, world!';

  // Encode the key and instantiate the codec.
  final blowfish = BlowfishECB(Uint8List.fromList(utf8.encode(key)));

  // Encrypt the input (with padding to fit the 8-bit block size).
  print('Encrypting "$message" with PKCS #5 padding.');
  final encryptedData =
      blowfish.encoder.convert(padPKCS5(utf8.encode(message)));

  // Decrypt the encrypted data.
  print('Decrypting "${hexEncode(encryptedData)}".');
  var decryptedData = blowfish.decoder.convert(encryptedData);
  // Remove PKCS5 padding.
  decryptedData = decryptedData.sublist(
      0, decryptedData.length - getPKCS5PadCount(decryptedData));
  print('Got "${utf8.decode(decryptedData)}".');
}

String hexEncode(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

Uint8List padPKCS5(List<int> input) {
  final inputLength = input.length;
  final paddingValue = 8 - (inputLength % 8);
  final outputLength = inputLength + paddingValue;

  final output = Uint8List(outputLength);
  for (var i = 0; i < inputLength; ++i) {
    output[i] = input[i];
  }
  output.fillRange(outputLength - paddingValue, outputLength, paddingValue);

  return output;
}

int getPKCS5PadCount(List<int> input) {
  if (input.length % 8 != 0) {
    throw FormatException('Block size is invalid!', input);
  }

  final count = input.last;
  final paddingStartIndex = input.length - count;
  for (var i = input.length - 1; i >= paddingStartIndex; --i) {
    if (input[i] != count) {
      throw FormatException('Padding is not valid PKCS5 padding!');
    }
  }

  return count;
}
