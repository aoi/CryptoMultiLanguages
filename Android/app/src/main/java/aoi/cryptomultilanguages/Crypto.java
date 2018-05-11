package aoi.cryptomultilanguages;

import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

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
}
