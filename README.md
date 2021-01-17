# Blowfish ECB for Dart

<p align="center">
<a href="https://pub.dev/packages/blowfish_ecb"><img src="https://img.shields.io/pub/v/blowfish_ecb?include_prereleases" alt="pub: blowfish_ecb"></a>
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-AGPL v3.0-green.svg" alt="License: AGPL"></a>
<a href="https://github.com/tenhobi/effective_dart"><img src="https://img.shields.io/badge/style-effective_dart-blue.svg" alt="style: effective dart"></a>
</p>

A pure Dart [Codec](https://api.dart.dev/stable/2.10.4/dart-convert/Codec-class.html)
implementation for the [Blowfish ECB](https://www.schneier.com/academic/blowfish/)
encryption algorithm.

## Usage
The `BlowfishECB` class fully implements [Codec](https://api.dart.dev/stable/2.10.4/dart-convert/Codec-class.html).

The following simple usage is adapted from the included example project:
```dart
// Encode the key and instantiate the codec.
final blowfish = BlowfishECB(key);

// Encrypt the input data.
final encryptedData = blowfish.encoder.convert(message);

// Decrypt the encrypted data.
final decryptedData = blowfish.decoder.convert(encryptedData);
```

## License
Everything is licenced under the GNU Lesser General Public License v3 or above.  
See [`LICENCE`](LICENSE) and [`LICENCE.LESSER`](LICENSE.LESSER) for more
information.

Essentially, if this code is modified in your project, the modified source code
for this package must be made available.

## Inspiration
The algorithm implementation was ported over from the
[Versile Python implementation](https://github.com/versiledev/versile-python/blob/master/versile/crypto/algorithm/blowfish.py).