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

// Loosely based on https://github.com/versiledev/versile-python/blob/master/versile/crypto/algorithm/blowfish.py

import 'dart:convert';
import 'dart:typed_data';

import 'package:blowfish_ecb/src/constants.dart';
import 'package:meta/meta.dart';

/// A Blowfish ECB [Codec] implementation.
class BlowfishECB extends Codec<List<int>, List<int>> {
  /// The size of a block of Blowfish ECB data.
  static const blockSize = 8;

  final List<int> p = _copyP(pInit);
  final List<List<int>> s = _copyS(sInit);

  BlowfishECB(Uint8List key) {
    final keyLength = key.length;

    if (keyLength > 56) {
      throw FormatException('Max key length is 448 bits (56 bytes)', key);
    }

    var j = 0;
    for (var i = 0; i < p.length; ++i) {
      var data = 0;
      for (var k = 0; k < 4; ++k) {
        data = ((data << 8) & 0xffffffff) | key[j];
        ++j;
        if (j >= keyLength) j = 0;
      }
      p[i] ^= data;
    }

    var data = Uint8List(8);
    for (var i = 0; i < p.length; i += 2) {
      BlowfishECBEncoder._encryptBlock(data, 0, p, s);
      p[i] = ((data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3]);
      p[i + 1] = ((data[4] << 24) + (data[5] << 16) + (data[6] << 8) + data[7]);
    }

    for (var i = 0; i < 4; ++i) {
      for (var j = 0; j < 256; j += 2) {
        BlowfishECBEncoder._encryptBlock(data, 0, p, s);
        s[i][j] =
            ((data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3]);
        s[i][j + 1] =
            ((data[4] << 24) + (data[5] << 16) + (data[6] << 8) + data[7]);
      }
    }
  }

  @override
  Converter<List<int>, Uint8List> get encoder => BlowfishECBEncoder(p, s);

  @override
  Converter<List<int>, Uint8List> get decoder => BlowfishECBDecoder(p, s);

  static List<int> _copyP(List<int> p) => List.of(p);

  static List<List<int>> _copyS(List<List<int>> s) =>
      List.generate(s.length, (index) => List.of(s[index]));
}

abstract class BlowfishECBConverter extends Converter<List<int>, Uint8List> {
  /// A base P list initialized with the key.
  final List<int> p;

  /// A base S list initialized with the key.
  final List<List<int>> s;

  const BlowfishECBConverter(this.p, this.s);

  @override
  Uint8List convert(List<int> input) {
    final result = Uint8List.fromList(input);
    _transform(
      result,
      BlowfishECB._copyP(p),
      BlowfishECB._copyS(s),
    );
    return result;
  }

  /// Starts a chunked conversion.
  ///
  /// The length of added chunks must be a multiple of 8.
  @override
  Sink<List<int>> startChunkedConversion(Sink<Uint8List> sink) {
    final p = BlowfishECB._copyP(this.p);
    final s = BlowfishECB._copyS(this.s);
    return BlowfishECBConverterSink(
      sink,
      (block) => _transform(block, p, s),
    );
  }

  @protected
  void transformBlock(
    Uint8List data,
    int startIndex,
    List<int> p,
    List<List<int>> s,
  );

  void _transform(
    Uint8List input,
    List<int> p,
    List<List<int>> s,
  ) {
    final length = input.length;
    if (length == 8) {
      transformBlock(input, 0, p, s);
    } else {
      if (length % 8 != 0) {
        throw FormatException('Data not aligned with 8-byte blocksize');
      }

      for (var start = 0; start < length; start += 8) {
        transformBlock(input, start, p, s);
      }
    }
  }

  static void _transformBlockCommon({
    required Uint8List data,
    required int startIndex,
    required List<int> p,
    required List<List<int>> s,
    required int loopStartAt,
    required int looopStopBefore,
    required int loopStep,
  }) {
    var bL = ((data[0 + startIndex] << 24) +
        (data[1 + startIndex] << 16) +
        (data[2 + startIndex] << 8) +
        data[3 + startIndex]);
    var bR = ((data[4 + startIndex] << 24) +
        (data[5 + startIndex] << 16) +
        (data[6 + startIndex] << 8) +
        data[7 + startIndex]);

    for (var i = loopStartAt; i != looopStopBefore; i += loopStep) {
      bL ^= p[i];
      bR ^= _feistel(bL, s);

      final swap = bL;
      bL = bR;
      bR = swap;
    }

    final swap = bL;
    bL = bR;
    bR = swap;

    bR ^= p[looopStopBefore];
    bL ^= p[looopStopBefore + loopStep];

    data[0 + startIndex] = bL >> 24;
    data[1 + startIndex] = bL >> 16;
    data[2 + startIndex] = bL >> 8;
    data[3 + startIndex] = bL;
    data[4 + startIndex] = bR >> 24;
    data[5 + startIndex] = bR >> 16;
    data[6 + startIndex] = bR >> 8;
    data[7 + startIndex] = bR;
  }

  static int _feistel(int x, List<List<int>> s) {
    final d = x & 0xff;
    x >>= 8;
    final c = x & 0xff;
    x >>= 8;
    final b = x & 0xff;
    x >>= 8;
    final a = x & 0xff;
    var y = (s[0][a] + s[1][b]) & 0xffffffff;
    y ^= s[2][c];
    y = (y + s[3][d]) & 0xffffffff;
    return y;
  }
}

class BlowfishECBConverterSink extends Sink<List<int>> {
  final Sink<Uint8List> output;
  final void Function(Uint8List block) transformBlock;

  BlowfishECBConverterSink(this.output, this.transformBlock);

  @override
  void add(List<int> chunk) {
    final block = Uint8List.fromList(chunk);
    transformBlock(block);
    output.add(block);
  }

  @override
  void close() => output.close();
}

class BlowfishECBEncoder extends BlowfishECBConverter {
  const BlowfishECBEncoder(List<int> p, List<List<int>> s) : super(p, s);

  @override
  void transformBlock(
    Uint8List data,
    int startIndex,
    List<int> p,
    List<List<int>> s,
  ) =>
      _encryptBlock(data, startIndex, p, s);

  static void _encryptBlock(
    Uint8List data,
    int startIndex,
    List<int> p,
    List<List<int>> s,
  ) =>
      BlowfishECBConverter._transformBlockCommon(
        data: data,
        startIndex: startIndex,
        p: p,
        s: s,
        loopStartAt: 0,
        looopStopBefore: 16,
        loopStep: 1,
      );
}

class BlowfishECBDecoder extends BlowfishECBConverter {
  const BlowfishECBDecoder(List<int> p, List<List<int>> s) : super(p, s);

  @override
  void transformBlock(
    Uint8List data,
    int startIndex,
    List<int> p,
    List<List<int>> s,
  ) =>
      _decryptBlock(data, startIndex, p, s);

  static void _decryptBlock(
    Uint8List data,
    int startIndex,
    List<int> p,
    List<List<int>> s,
  ) =>
      BlowfishECBConverter._transformBlockCommon(
        data: data,
        startIndex: startIndex,
        p: p,
        s: s,
        loopStartAt: 17,
        looopStopBefore: 1,
        loopStep: -1,
      );
}
