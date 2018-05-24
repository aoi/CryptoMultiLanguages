# Crypto Multi Languages

AES Encrypt - Decrypt / Create key pair / Key pair Encrypt - Decrypt / Sign - Verify between multi languages.  

 - Node.js(8.9.4)
 - Android Java(API Level 23 / 1.8)
 - Java(1.8)

## AES Encrypt - Decrypt
AES128/ECB/PKCS5Padding  
AES128/CBC/PKCS5Padding  

(AES256 is available on API Level 26+ ? https://developer.android.com/reference/javax/crypto/Cipher)  
(AES256 is available on Java 9+ ? without policy file)

## Create key pair
Create private key / public key with pem format.  
size 2048.  

## Key pair Encrypt

 - private key encrypt  
    - RSA/ECB/PKCS1Padding
 - private key decrypt
    - RSA/ECB/OAEPPadding
 - public key encrypt
    - RSA/ECB/OAEPPadding
 - public key decrypt
    - RSA/ECB/PKCS1Padding

Node.js Reference  
https://nodejs.org/docs/latest-v8.x/api/crypto.html  

## Sign - Verify
SHA256withRSA

## Usage
### Node.js

```
cd Node.js
npm install
npm test
```

### Android
Open project in Android Studio, then run CryptoTest.java  

### Java  
Open project in Eclipse, then run CryptoTest.java  
