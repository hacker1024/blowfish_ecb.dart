import 'dart:convert';
import 'dart:typed_data';

import 'package:blowfish_ecb/src/tables.dart';
import 'package:meta/meta.dart';

abstract class BlowfishECBConverter extends Converter<List<int>, Uint8List> {
  /// A base P list initialized with the key.
  final List<int> p;

  /// A base S list initialized with the key.
  final List<List<int>> s;

  const BlowfishECBConverter(this.p, this.s);

  /// Encrypts or decrypts the given [input], returning a new [Uint8List] with
  /// the output.
  @override
  Uint8List convert(List<int> input) {
    final result = Uint8List.fromList(input);
    _transform(
      result,
      copyP(p),
      copyS(s),
    );
    return result;
  }

  /// Starts a chunked conversion.
  ///
  /// The length of added chunks must be a multiple of 8.
  @override
  Sink<List<int>> startChunkedConversion(Sink<Uint8List> sink) {
    return _BlowfishECBConverterSink(
      sink,
      (block) => _transform(
        block,
        copyP(p),
        copyS(s),
      ),
    );
  }

  @protected
  void _transformBlock(
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
      _transformBlock(input, 0, p, s);
    } else {
      if (length % 8 != 0) {
        throw FormatException('Data not aligned with 8-byte blocksize');
      }

      for (var start = 0; start < length; start += 8) {
        _transformBlock(input, start, p, s);
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

class _BlowfishECBConverterSink extends Sink<List<int>> {
  final Sink<Uint8List> output;
  final void Function(Uint8List block) transformBlock;

  _BlowfishECBConverterSink(this.output, this.transformBlock);

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
  void _transformBlock(
    Uint8List data,
    int startIndex,
    List<int> p,
    List<List<int>> s,
  ) =>
      encryptBlock(data, startIndex, p, s);

  /// Encrypts an 8-byte block of data in an existing list of [data], starting
  /// at [startIndex].
  ///
  /// This is used internally by the package and should not need to be called in
  /// any other situation.
  static void encryptBlock(
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
  void _transformBlock(
    Uint8List data,
    int startIndex,
    List<int> p,
    List<List<int>> s,
  ) =>
      _decryptBlock(data, startIndex, p, s);

  /// Decrypts an 8-byte block of data in an existing list of [data], starting
  /// at [startIndex].
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
