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

import 'package:blowfish_ecb/src/blowfish_ecb_converter.dart';
import 'package:blowfish_ecb/src/tables.dart';

/// A Blowfish ECB [Codec] implementation.
class BlowfishECB extends Codec<List<int>, List<int>> {
  /// The size of a block of Blowfish ECB data.
  ///
  /// All data must be a multiple of this number in length.
  static const blockSize = 8;

  final List<int> _p = copyP(pInit);
  final List<List<int>> _s = copyS(sInit);

  /// A [Converter] that encrypts data.
  @override
  Converter<List<int>, Uint8List> get encoder => BlowfishECBEncoder(_p, _s);

  /// A [Converter] that decrypts data.
  @override
  Converter<List<int>, Uint8List> get decoder => BlowfishECBDecoder(_p, _s);

  /// Creates an instance of the codec initialized with the given [key].
  BlowfishECB(Uint8List key) {
    final keyLength = key.length;

    if (keyLength > 56) {
      throw FormatException('Max key length is 448 bits (56 bytes)', key);
    }

    var j = 0;
    for (var i = 0; i < _p.length; ++i) {
      var data = 0;
      for (var k = 0; k < 4; ++k) {
        data = ((data << 8) & 0xffffffff) | key[j];
        ++j;
        if (j >= keyLength) j = 0;
      }
      _p[i] ^= data;
    }

    final data = Uint8List(8);
    for (var i = 0; i < _p.length; i += 2) {
      BlowfishECBEncoder.encryptBlock(data, 0, _p, _s);
      _p[i] = (data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3];
      _p[i + 1] = (data[4] << 24) + (data[5] << 16) + (data[6] << 8) + data[7];
    }

    for (var i = 0; i < 4; ++i) {
      for (var j = 0; j < 256; j += 2) {
        BlowfishECBEncoder.encryptBlock(data, 0, _p, _s);
        _s[i][j] = (data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3];
        _s[i][j + 1] =
            (data[4] << 24) + (data[5] << 16) + (data[6] << 8) + data[7];
      }
    }
  }
}
