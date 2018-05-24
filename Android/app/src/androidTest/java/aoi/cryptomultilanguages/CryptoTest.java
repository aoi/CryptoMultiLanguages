package aoi.cryptomultilanguages;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;
import android.util.Base64;
import android.util.Log;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Created by aoi on 2018/05/11.
 */
@RunWith(AndroidJUnit4.class)
public class CryptoTest {

    private static final String DATA = "This is important data.";
    private static final String PASSWORD = "pass";
    private Crypto crypto;

    @Before
    public void before() {
        crypto = new Crypto(InstrumentationRegistry.getTargetContext());
    }

    @Test
    public void testEncrypt_AES128_ECB_PKCS5Padding() throws Exception {
        String encData = crypto.encrypt_AES128_ECB_PKCS5Padding(DATA, PASSWORD);

        assertEquals("RFGeILFKldYRG/8J88ClKhNrqXPH8GLPqMnqFuFzDc0=", encData);
    }

    @Test
    public void testDecrypt_AES128_ECB_PKCS5Padding() {
        String decData = crypto.decrypt_AES128_ECB_PKCS5Padding("RFGeILFKldYRG/8J88ClKhNrqXPH8GLPqMnqFuFzDc0=", PASSWORD);

        assertEquals(DATA, decData);
    }

    @Test
    public void testCreateRsaKeyPair() {
        crypto.createRsaKeyPair();
    }

    @Test
    public void testJavaPrivateEncryptPublicDecrypt() {
        String e = crypto.privateEncrypt(DATA, "java_private.pem");
        String d = crypto.publicDecrypt(e, "java_public.pem");

        assertEquals(DATA, d);
    }

    @Test
    public void testJavaPublicEncryptPrivateDecrypt() {
        String e = crypto.publicEncrypt(DATA, "java_public.pem");
        String d = crypto.privateDecrypt(e, "java_private.pem");

        assertEquals(DATA, d);
    }

    @Test
    public void testNodejsPrivateEncryptPublicDecrypt() {
        String e = crypto.privateEncrypt(DATA, "nodejs_private.pem");
        String d = crypto.publicDecrypt(e, "nodejs_public.pem");

        assertEquals(DATA, d);
    }

    @Test
    public void testNodejsPublicEncryptPrivateDecrypt() {
        String e = crypto.publicEncrypt(DATA, "nodejs_public.pem");
        String d = crypto.privateDecrypt(e, "nodejs_private.pem");

        assertEquals(DATA, d);
    }

    @Test
    public void testPrivateDecrypt() {
        // encrypted by Node.js
        String encData = "SZRgiuyiovKsA8gvzYhWkgtqg8gzL80a77Yt3jOXE6NOksWaPoLIGjxbV4I7+XpwQtNSPnugMenwBUR0fAoA2ygoLVIw+hNzQkRXPwr4PsEhVuh3g2k9idXDjiSNDk7sOtOn3CA85LVFJuw7N2CSPPpgne7zrdu1qbsvtlcLaoH01JN4dS69R41JFAe74MtVYV/jeiyiPsxYfIgfDS5C7kgxi6MMFksDUQ8vyQwB8WP58DKDYZdRE0HPANeDNpraJjix9qICwTrUjN9olDc2on3WdQzR9XNFdsgaeDaNvOHPrPjhHEFQma4GhnsY5YvRiFJf7ZOJuDn0TNxmOUKqKw==";
        String decData = crypto.privateDecrypt(encData, "nodejs_private.pem");

        assertEquals(DATA, decData);
    }

    @Test
    public void testPublicDecrypt() {
        // encrypted by Node.js
        String encData = "BRNlIuGQfgzufPyxOHRAeirfFd2Ezm5QXixh2C/4UFJBlcMIFpgpqJGbvF6pUssGyfO3cfFclm0V3ir+prWcqk/hdwjoJsy5zdn+K/nVJ+P0aVqjvoWflHa/DTPN6zMvJMX0xyb3W9iPbLWYuxwe/vfOpZZryb1u8r2NsyDwlR3rNNUhIij+Ls7M8aXCPbcKgQxHld3Ioyvg9Yj2FwaJyBbflE/wyZyJplgn+QYvb1TA+8QwnP/aPAAJWRvgX7U9Pv61zZjxn/gT1bq0iw5pVP87buTQhL+WZ2VtPP0lT7Cv6J3OU4r0iGHkfZCrFRh5/0h2LqmFJQ1tW5GPwrR7sw==";
        String decData = crypto.publicDecrypt(encData, "nodejs_public.pem");

        assertEquals(DATA, decData);
    }

    @Test
    public void testJavaSignVerify() {
        String signature = crypto.sign(DATA, "java_private.pem");
        boolean result = crypto.verify(signature, DATA,"java_public.pem");

        assertTrue(result);
    }

    @Test
    public void testVerify() {
        // signed by Node.js
        String signature = "eJBpgJdqH7PZm5GJMKMGBpEjE9Sf3v8X02PgKZphyzrdxZxJNbAgNbrzbFoC8mmfDzn1IDgY6UVh1srxtUX4bcgvfvKDcyLmcpQIenrlAkON70tCwxosZatnl2YVaAcZ18UyXx1QS0UgQMH2WKtZ0CV6E7Ee7a+y5K72ef9R/oOoJZdy6SWAc36k8wqC+Eed7+wrFZMkyCWwGjSKp0KsLitQLvH7mj17IZxbjp4NSiP63k7tArcj21AJJgBXvtM/6JjpP2x4kkKk9ww39ysJsDAF5jRZsvU3Qg+preYd0fWKm30NXpUP8MM7KFG+yar+gNLdfpy7Bjpkr3lFkOPOXA==";
        boolean result = crypto.verify(signature, DATA, "nodejs_public.pem");

        assertTrue(result);
    }
 }