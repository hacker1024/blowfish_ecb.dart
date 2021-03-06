/*
Blowfish ECB dart:convert Codec implementation.
Copyright (C) 2021 hacker1024

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:blowfish_ecb/src/blowfish_ecb.dart';
import 'package:test/test.dart';

import 'constants.dart';

void main() {
  group(
    'Algorithm',
    () {
      late BlowfishECB blowfish;

      setUp(() => blowfish = BlowfishECB(Uint8List.fromList(sampleKey)));

      test(
        'Encryption',
        () {
          final encryptedData =
              blowfish.encode(Uint8List.fromList(sampleDecryptedData));

          expect(encryptedData, equals(sampleEncryptedData));
        },
      );

      test(
        'Decryption',
        () {
          final decryptedData =
              blowfish.decode(Uint8List.fromList(sampleEncryptedData));

          expect(decryptedData, equals(sampleDecryptedData));
        },
      );
    },
  );

  group(
    'Chunked conversions',
    () {
      Future<void> testChunkedConversion(
        Converter<List<int>, Uint8List> converter,
        List<int> input,
        List<int> expectedOutput,
      ) async {
        final completer = Completer<List<int>>();

        final inputSink = converter.startChunkedConversion(
          ChunkedConversionSink<Uint8List>.withCallback(
            (chunks) =>
                completer.complete([for (final chunk in chunks) ...chunk]),
          ),
        );
        // Add the data in two groups to simulate chunks going through.
        inputSink.add(input.sublist(0, 32));
        inputSink.add(input.sublist(32));
        inputSink.close();

        expect(await completer.future, equals(expectedOutput));
      }

      late BlowfishECB blowfish;

      setUp(() => blowfish = BlowfishECB(Uint8List.fromList(sampleKey)));

      test(
        'Encryption',
        () => testChunkedConversion(
          blowfish.encoder,
          sampleDecryptedData,
          sampleEncryptedData,
        ),
      );

      test(
        'Decryption',
        () => testChunkedConversion(
          blowfish.decoder,
          sampleEncryptedData,
          sampleDecryptedData,
        ),
      );
    },
  );

  group(
    'Validation',
    () {
      test(
        'Key size should be at most 56 bytes.',
        () {
          expect(
              () => BlowfishECB(Uint8List(56)), isNot(throwsFormatException));
          expect(() => BlowfishECB(Uint8List(57)), throwsFormatException);
        },
      );

      test(
        'Data must be padded to block sizes of 8',
        () {
          final blowfish = BlowfishECB(Uint8List.fromList(sampleKey));

          // Encoding
          expect(() => blowfish.encode(Uint8List(200)),
              isNot(throwsFormatException));
          expect(() => blowfish.encode(Uint8List(201)), throwsFormatException);

          // Decoding
          expect(() => blowfish.decode(Uint8List(200)),
              isNot(throwsFormatException));
          expect(() => blowfish.decode(Uint8List(201)), throwsFormatException);
        },
      );
    },
  );
}
