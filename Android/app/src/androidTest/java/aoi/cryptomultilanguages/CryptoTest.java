package aoi.cryptomultilanguages;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;

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
        crypto = new Crypto();
    }

    @Test
    public void testEncryptoAes128() throws Exception {
        String encData = crypto.encrypt_AES128_ECB_PKCS5Padding(DATA, PASSWORD);

        assertEquals("RFGeILFKldYRG/8J88ClKhNrqXPH8GLPqMnqFuFzDc0=", encData);
    }

    @Test
    public void testDecryptoAes128() {
        String decData = crypto.decrypt_AES128_ECB_PKCS5Padding("RFGeILFKldYRG/8J88ClKhNrqXPH8GLPqMnqFuFzDc0=", PASSWORD);

        assertEquals(DATA, decData);
    }
}
