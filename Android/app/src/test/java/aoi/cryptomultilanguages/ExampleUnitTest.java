package aoi.cryptomultilanguages;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {

    private static final String DATA = "This is important data.";
    private static final String PASSWORD = "pass";

    @Test
    public void addition_isCorrect() throws Exception {
        Crypto crypto = new Crypto();
        String encData = crypto.encryptAes128(DATA, PASSWORD);

        assertEquals("RFGeILFKldYRG/8J88ClKhNrqXPH8GLPqMnqFuFzDc0=", encData);
    }
}