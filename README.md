# react-native-minds-crypto

A native implementation of RSA encryption/decryption, sign/verify.
Implementation is in PKCS1 for public
Implementation is in PKCS8 for private

## Support

iOS 10+
android 4.1+ (API 16)

## Status

Features:
Encryption,
Decryption,
Sign,
Verify

## Getting started

`$ yarn add react-native-minds-crypto`

or:

`$ npm install react-native-minds-crypto --save`

### Mostly automatic installation:

`$ react-native link react-native-minds-crypto`

## iOS

In your React Native Xcode project, right click on your project and go 'Add Files to ...', then navigate to <your-project-root>/node_modules/react-native-minds-crypto/ios and select the Crypto.xcodeproj file. Then in the build settings for your target under 'Link Binary With Libraries', add libCrypto.a.

## Usage

```

import Encryption from 'react-native-minds-encryption';

const publicKey = '...';
const privateKey = '...';
const secret = '...';

Encryption.encrypt('1234', publickey)
  .then(encodedMessage => {
    Encryption.decrypt(encodedMessage, privateKey)
      .then(message => {
        console.log(message);
      });
  });

Encryption.sign(secret, keys.private)
  .then(signature => {
    console.log(signature);

    Encryption.verify(signature, secret, publicKey)
      .then(valid => {
        console.log(valid);
      });
  });


## Credit

* Based on https://github.com/amitaymolko/react-native-rsa-native
