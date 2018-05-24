package aoi.cryptomultilanguages;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

public class CryptoTest {
	
	private static final String DATA = "This is important data.";
	private static final String PASSWORD = "pass";
	
	private Crypto crypto;
	
	@Before
	public void before() {
		crypto = new Crypto();
	}

	@Test
	public void testEncrypt_AES128_CBC_PKCS5Padding() {
		crypto.encrypt_AES128_CBC_PKCS5Padding(DATA, PASSWORD);
	}
	
	@Test
	public void testDecrypt_AES128_CBC_PKCS5Padding() {
		String ivB64 = "4BzBMSEdWayB5lzZjE64Xg==";
		String encData = "OvSkSxupiqM0N4keI9nZ2hGpgep4/b+i2QgtTNd42uM=";
		
		String data = crypto.decrypt_AES128_CBC_PKCS5Padding(encData, PASSWORD, ivB64);
		
		assertEquals(DATA, data);
	}
}
