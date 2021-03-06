# Blowfish ECB for Dart

<p align="center">
<a href="https://pub.dev/packages/blowfish_ecb"><img src="https://img.shields.io/pub/v/blowfish_ecb" alt="pub: blowfish_ecb"></a>
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-AGPL v3.0-green.svg" alt="License: AGPL"></a>
<a href="https://pub.dev/packages/lint"><img src="https://img.shields.io/badge/style-lint-4BC0F5.svg" alt="style: lint"></a>
</p>

A pure Dart [Codec](https://api.dart.dev/stable/2.10.4/dart-convert/Codec-class.html)
implementation for the [Blowfish ECB](https://www.schneier.com/academic/blowfish/)
encryption algorithm.

## Usage
The `BlowfishECB` class fully implements [Codec](https://api.dart.dev/stable/2.10.4/dart-convert/Codec-class.html).

The following simple usage is adapted from the included example project:
```dart
// Instantiate the codec with a key.
final blowfish = BlowfishECB(key);

// Encrypt the input data.
final encryptedData = blowfish.encode(message);

// Decrypt the encrypted data.
final decryptedData = blowfish.decode(encryptedData);
```

## License
Everything is licenced under the GNU Lesser General Public License v3 or above.  
See [`LICENCE`](LICENSE) and [`LICENCE.LESSER`](LICENSE.LESSER) for more
information.

Essentially, if this package is modified in your project, the modified package
sources must be released.

## Inspiration
The algorithm implementation was ported over from the
[Versile Python implementation](https://github.com/versiledev/versile-python/blob/master/versile/crypto/algorithm/blowfish.py).