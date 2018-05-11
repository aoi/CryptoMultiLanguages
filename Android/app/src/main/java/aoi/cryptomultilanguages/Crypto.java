package aoi.cryptomultilanguages;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by aoi on 2018/05/11.
 */

public class Crypto {

    private static final String TAG = "Crypto";
    private Context context;

    public Crypto (Context context) {
        this.context = context;
    }

    public String encrypt_AES128_ECB_PKCS5Padding(String data, String password) {
        password += "0000000000000000";
        password = password.substring(0 ,16);

        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // 128

            SecretKeySpec key = new SecretKeySpec(password.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encDataB = cipher.doFinal(data.getBytes());
            String encData = Base64.encodeToString(encDataB, Base64.DEFAULT);
            encData = encData.trim();
            Log.d(TAG, "encData: " + encData);

            return encData;

        } catch (NoSuchAlgorithmException |NoSuchPaddingException |BadPaddingException |InvalidKeyException |IllegalBlockSizeException e) {
            Log.d(TAG, e.getMessage(), e);
        }

        return null;
    }

    public String decrypt_AES128_ECB_PKCS5Padding(String encData, String password) {
        password += "0000000000000000";
        password = password.substring(0 ,16);

        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

            SecretKeySpec key = new SecretKeySpec(password.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] dataB = cipher.doFinal(Base64.decode(encData.getBytes(), Base64.DEFAULT));
            String data = new String(dataB, "UTF-8");

            Log.d(TAG, "data: " + data);

            return data;

        } catch (NoSuchAlgorithmException|NoSuchPaddingException|BadPaddingException|InvalidKeyException|IllegalBlockSizeException|UnsupportedEncodingException e) {
            Log.d(TAG, e.getMessage(), e);
        }

        return null;
    }

    public void createRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            Key publicKey = pair.getPublic();
            Key privateKey = pair.getPrivate();
            String pub = Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT);
            String pri = Base64.encodeToString(privateKey.getEncoded(), Base64.DEFAULT);

            pub = "-----BEGIN PUBLIC KEY-----\n" + pub + "-----END PUBLIC KEY-----\n";
            pri = "-----BEGIN PRIVATE KEY-----\n" + pri + "-----END PRIVATE KEY-----\n";

            Log.d(TAG, "publicKey: " + pub);
            Log.d(TAG, "privateKey: " + pri);
        } catch(NoSuchAlgorithmException e) {
            Log.e(TAG, e.getMessage());
        }
    }

    public String privateEncrypt(String data, String keyFileName) {

        try {
            PrivateKey key = this.getPrivateKey(keyFileName);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            String enc = Base64.encodeToString(encryptedData, Base64.DEFAULT);
            enc = enc.replaceAll("\n", "");
            Log.d(TAG, "privateEncrypt " + keyFileName + ": " + enc);
            return enc;

        } catch(NoSuchAlgorithmException|InvalidKeyException|NoSuchPaddingException|BadPaddingException|IllegalBlockSizeException e) {
            Log.e(TAG, e.getMessage(), e);
        }

        return null;
    }

    public String privateDecrypt(String encData, String keyFileName) {

        try {
            PrivateKey key = this.getPrivateKey(keyFileName);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] dataB = cipher.doFinal(Base64.decode(encData, Base64.DEFAULT));

            String data = new String(dataB, "UTF-8");
            Log.d(TAG, "privateDecrypt:" + data);
            return data;

        } catch(UnsupportedEncodingException|NoSuchAlgorithmException|InvalidKeyException|NoSuchPaddingException|BadPaddingException|IllegalBlockSizeException e) {
            Log.e(TAG, e.getMessage(), e);
        }

        return null;
    }

    public String publicEncrypt(String data, String keyFileName) {

        try {
            PublicKey key = this.getPublicKey(keyFileName);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            String enc = Base64.encodeToString(encryptedData, Base64.DEFAULT);
            enc = enc.replaceAll("\n", "");
            Log.d(TAG, "publicEncrypt " + keyFileName + ": " + enc);

            return enc;
        } catch(NoSuchAlgorithmException|InvalidKeyException|NoSuchPaddingException|BadPaddingException|IllegalBlockSizeException e) {
            Log.e(TAG, e.getMessage(), e);
        }

        return null;
    }

    public String publicDecrypt(String encData, String keyFileName) {

        try {
            PublicKey key = this.getPublicKey(keyFileName);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] dataB = cipher.doFinal(Base64.decode(encData, Base64.DEFAULT));

            String data = new String(dataB, "UTF-8");
            Log.d(TAG, "publicDecrypt:" + data);
            return data;

        } catch(UnsupportedEncodingException|NoSuchAlgorithmException|InvalidKeyException|NoSuchPaddingException|BadPaddingException|IllegalBlockSizeException e) {
            Log.e(TAG, e.getMessage(), e);
        }

        return null;
    }

    public String sign(String data, String keyFileName) {

        try {
            PrivateKey key = getPrivateKey(keyFileName);

            // Sign
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(key);
            signature.update(data.getBytes());
            byte[] signB = signature.sign();
            String s = Base64.encodeToString(signB, Base64.DEFAULT);
            s = s.replaceAll("\n", "");
            Log.d(TAG, "sign: " + s);
            return s;
        } catch (NoSuchAlgorithmException|SignatureException |InvalidKeyException e) {
            Log.e(TAG, e.getMessage(), e);
        }

        return null;
    }

    public boolean verify(String signature, String data, String keyFileName) {

        try {
            PublicKey key = this.getPublicKey(keyFileName);

            // Verify
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(key);
            sig.update(data.getBytes());
            return sig.verify(Base64.decode(signature, Base64.DEFAULT));

        } catch(NoSuchAlgorithmException|InvalidKeyException|SignatureException e) {
            Log.e(TAG, e.getMessage(), e);
        }

        return false;
    }

    private PublicKey getPublicKey(String keyFileName) {
        String key = readAssets(keyFileName);
        key = key.replaceAll("-----.* KEY-----\n", "");

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(key, Base64.DEFAULT));
        KeyFactory kf = null;

        try {
            kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException|InvalidKeySpecException e) {
            Log.e(TAG, e.getMessage(), e);
        }

        return null;
    }

    private PrivateKey getPrivateKey(String keyFileName) {
        String k = readAssets(keyFileName);
        k = k.replaceAll("-----.* KEY-----\n", "");

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(k, Base64.DEFAULT));
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException|InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }

    private String readAssets(String fileName) {
        InputStream is = null;
        BufferedReader br = null;
        String p = "";

        try {
            is = this.context.getAssets().open(fileName);
            br = new BufferedReader(new InputStreamReader(is));

            String line;
            while((line = br.readLine()) != null) {
                p += line + "\n";
            }
        } catch (IOException e) {
            Log.d(TAG, e.getMessage(), e);
        } finally {
            try {
                if (is != null) { is.close(); }
                if (br != null) { br.close(); }
            } catch(Exception e) {}
        }

        return p;
    }
}
