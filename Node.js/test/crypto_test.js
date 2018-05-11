'use strict';
const assert = require('assert');
const fs = require('fs');
const crypto = require('crypto');
const keypair = require('keypair');
const forge = require('node-forge');

describe('Crypto Test', function(){
  this.timeout(0);

  const PASSWORD = 'pass';
  const DATA = 'This is important data.';

  it('Encrypt AES128 ECB PKCS5Padding', function(done){

    const cipher = crypto.createCipheriv('aes-128-ecb', paddingPassword(PASSWORD), '');
    let e = cipher.update(DATA, 'utf8', 'base64');
    e += cipher.final('base64');

    assert.equal(e, 'RFGeILFKldYRG/8J88ClKhNrqXPH8GLPqMnqFuFzDc0=');

    done();
  });

  it('Decrypt AES128 ECB PKCS5Padding', function(done){
    const encData = 'RFGeILFKldYRG/8J88ClKhNrqXPH8GLPqMnqFuFzDc0=';

    const decipher = crypto.createDecipheriv('aes-128-ecb', paddingPassword(PASSWORD), '');
    let d = decipher.update(encData, 'base64', 'utf8');
    d += decipher.final('utf8');

    assert.equal(d, DATA);

    done();
  });

  it('Create RSA Key Pair', function(done) {
    const pair = keypair();
    const privateKey = forge.pki.privateKeyFromPem(pair.private);
    //let priPem = forge.pki.privateKeyToPem(privateKey);
    const priAsn1 = forge.pki.privateKeyToAsn1(privateKey);
    const privateKeyInfo = forge.pki.wrapRsaPrivateKey(priAsn1);
    let priPem = forge.pki.privateKeyInfoToPem(privateKeyInfo);
    priPem = priPem.replace(/\r\n/g, '\n');
    const publicKey = forge.pki.publicKeyFromPem(pair.public);
    let pubPem = forge.pki.publicKeyToPem(publicKey);
    pubPem = pubPem.replace(/\r\n/g, '\n');

    console.log(priPem);
    console.log(pubPem);

    done();
  });

  it('Node.js privateEncrypt -> publicDecrypt', function(done) {
    const e = privateEncrypt(DATA, './test/nodejs_private.pem');
    console.log(e);
    const d = publicDecrypt(e, './test/nodejs_public.pem');

    assert.equal(d, DATA);
    done();
  });

  it('Node.js publicEncrypt -> privateDecrypt', function(done) {
    const e = publicEncrypt(DATA, './test/nodejs_public.pem');
    console.log(e);
    const d = privateDecrypt(e, './test/nodejs_private.pem');

    assert.equal(d, DATA);
    done();
  });

  it('Java privateEncrypt -> publicDecrypt', function(done) {
    const e = privateEncrypt(DATA, './test/java_private.pem');
    console.log(e);
    const d = publicDecrypt(e, './test/java_public.pem');

    assert.equal(d, DATA);
    done();
  });

  it('Java publicEncrypt -> privateDecrypt', function(done) {
    const e = publicEncrypt(DATA, './test/java_public.pem');
    console.log(e);
    const d = privateDecrypt(e, './test/java_private.pem');

    assert.equal(d, DATA);
    done();
  });

  it('privateDecrypt', function(done) {
    // encrypted by Java
    const encData = 'QM45GcyaAEDRU0SmehAiXL1mkPmOdoAljnNq+tKE4r1/+pKXLqYAWFMS/6dwz9O5AfcgB849AhJNnyYbDnjhlVJFodoQepRhg1MdkG//honCnlzygTqg3EF/znlaEP9xQJ1wLYNxhhLG6WB4FfKV4aXzih96APhEueiY906S3koG7PQWYpwI0gmtcz07vG2w73KqUf3/MARtGOw048eE8CdXuOsM816RJrHwXtRJNJX1Gba5JQldS90N3Alh0OnoTwk2BIzorOWfkXC4ykdfoBN609k+lnkR4DrNugAoQkX0EbXTeZKZxjKUryR3GWQnu2onFXlznOXs8pqTzj75RA==';
    const d = privateDecrypt(encData, './test/java_private.pem');

    assert.equal(d, DATA);
    done();
  });

  it('publicDecrypt', function(done) {
    // encrypted by Java
    const encData = 'Ovd9xqzb+mDaGxyzLpubgUIDTvbCmDBpwkk27Q7xyTaCwAcfa5V9ew5SecbL5xZeO6/UIzohp9UcNHiRJslHzKLdMaGtuNJkniSh0L4O5VFPWRs3nnbqfDrctvje2Dz1Mvpttd1PXHHxDLqH0bznSZHOD6/Z8s7hAkuOe/MQejYlPe+tt8zAa199Z9h/MjrA8rdRCj2zbNFLaVLa6PxFd1tE2L87nM4V+YQP8zsfEhegq/0yisUnbXMf8v54Yh8DNwX2TXGBjN4w3O3lETKBhasKtCbJYvS8EL1HRWsjl8BZcBMy39bkCcKgJopl5yG0i9lcJJMWEdi9dnyrC2qLbA==';
    const d = publicDecrypt(encData, './test/java_public.pem');

    assert.equal(d, DATA);
    done();
  });

  it('Node.js sign -> veriy', function(done){
    const signature = sign('./test/nodejs_private.pem');
    console.log(signature);
    const result = verify(signature, './test/nodejs_public.pem');
    console.log(result);

    assert.equal(result, true);

    done();
  });

  it('Java sign -> verify', function(done) {
    const signature = sign('./test/java_private.pem');
    const result = verify(signature, './test/java_public.pem');

    assert.equal(result, true);
    done();
  });

  it('verify', function(done) {
    // signed by Java
    const signature = 'mppveTWIx9g3zw+mUtx8HejuRF2UFB0jtUNzYlZDhv+dDSOoChMWjXDrffLSh6nD/vR3x8Qo2bNLWC2itFRd5o54Hsrt9am4oRMiRrnLKr2O/TxSvvAnGxM3G49HxyjNfi/1CToWlFkFFJAwOGO0lKnFT33Vm54GBLDBU3R4n3sJzaTFlZuyLAA0oDt+HAGtJgK/O2SeQp4VsThc44uyOgNZKlbBiq7aOozy67B1lBHT0fEldA431SgxoK8ys6+kSX0KGr5qv+DOvPRerqH/CXnPnmuxx170YpQfREwOxCNc379V/8djNmYXjkgwOAsPDWzZkL/itYeK+qFERKGzHA==';
    const result = verify(signature, './test/java_public.pem');

    assert.equal(result, true);
    done();
  });

  function privateEncrypt(data, privateKeyFileName) {
    const key = fs.readFileSync(privateKeyFileName, {encoding: 'ascii'});
    const eBuf = crypto.privateEncrypt(key, new Buffer(DATA));
    return eBuf.toString('base64');
  }

  function privateDecrypt(encData, privateKeyFileName) {
    const key = fs.readFileSync(privateKeyFileName, {encoding: 'ascii'});
    const dBuf = crypto.privateDecrypt(key, new Buffer(encData, 'base64'));
    return dBuf.toString();
  }

  function publicEncrypt(data, publicKeyFileName) {
    const key = fs.readFileSync(publicKeyFileName, {encoding: 'ascii'});
    const eBuf = crypto.publicEncrypt(key, new Buffer(DATA));
    return eBuf.toString('base64');
  }

  function publicDecrypt(encData, publicKeyFileName) {
    const key = fs.readFileSync(publicKeyFileName, {encoding: 'ascii'});
    const dBuf = crypto.publicDecrypt(key, new Buffer(encData, 'base64'));
    return dBuf.toString();
  }

  function sign(keyFileName) {
    const pri = fs.readFileSync(keyFileName, {encoding: 'ascii'});
    var sign = crypto.createSign('RSA-SHA256');
    sign.update(DATA);
    return sign.sign(pri, 'base64');
  }

  function verify(signature, keyFileName) {
    const pub = fs.readFileSync(keyFileName, {encoding: 'ascii'});
    const verify = crypto.createVerify('SHA256');
    verify.update(DATA);
    return verify.verify(pub, new Buffer(signature, 'base64'));
  }

  function paddingPassword(password) {
    return (password + '0000000000000000').substring(0, 16);
  }

});
