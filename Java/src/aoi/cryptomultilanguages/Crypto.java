package aoi.cryptomultilanguages;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {

	public String encrypt_AES128_CBC_PKCS5Padding(String data, String password) {
		password += "0000000000000000";
        password = password.substring(0 ,16);

        byte[] iv = new byte[16];
        new Random().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        try {
        	
        	
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // 128

            SecretKeySpec key = new SecretKeySpec(password.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] encDataB = cipher.doFinal(data.getBytes());
            String encData = Base64.getEncoder().encodeToString(encDataB);
            encData = encData.trim();
            System.out.println("iv base64: " + Base64.getEncoder().encodeToString(iv));
            System.out.println("encData: " + encData);

            return encData;

        } catch (NoSuchAlgorithmException|NoSuchPaddingException
        		|BadPaddingException|InvalidKeyException|IllegalBlockSizeException
        		|InvalidAlgorithmParameterException e) {
        	e.printStackTrace();
        }

        return null;
	}
	
	public String decrypt_AES128_CBC_PKCS5Padding(String encData, String password, String ivB64) {
		password += "0000000000000000";
        password = password.substring(0 ,16);
        
        byte[] iv = Base64.getDecoder().decode(ivB64);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            SecretKeySpec key = new SecretKeySpec(password.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] dataB = cipher.doFinal(Base64.getDecoder().decode(encData));
            String data = new String(dataB, "UTF-8");

            System.out.println("data: " + data);

            return data;

        } catch (NoSuchAlgorithmException|NoSuchPaddingException
        		|BadPaddingException|InvalidKeyException|IllegalBlockSizeException
        		|InvalidAlgorithmParameterException|UnsupportedEncodingException e) {
        	e.printStackTrace();
        }

        return null;
	}
}
