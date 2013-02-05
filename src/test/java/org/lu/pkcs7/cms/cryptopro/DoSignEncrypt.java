package org.lu.pkcs7.cms.cryptopro;

import org.lu.pki.tools.CryptoProCryptoUtils;
import org.lu.pki.tools.CryptoUtils;

public class DoSignEncrypt {
	
	public static final String[] SIGNERS = new String[]{"luxoft-test2"};
	
	public static final String[] RECIPIENTS = new String[]{"barankevich2012.cer", "pivsaeva_2012_tcs", "luxoft-test1"}; 
	
	public static final String ENCRYPTED_FILE = "C:\\developer\\temp\\cryptopro_enveloped.p7m";
	
	public static void main(String... args) throws Exception {
			
		byte[] sourceData = "bu-bu777888-000-111-222".getBytes();
		
		System.out.println("Source data length " + sourceData.length +'b');
		
		CryptoUtils cputilsE = new CryptoProCryptoUtils("C:/Users/user1/Documents/444", "123"); 
		
		System.out.println(cputilsE.getAllAliases().toString());
		
		byte[] encrypted = cputilsE.signer(SIGNERS).recipients(RECIPIENTS).actions(sourceData, ENCRYPTED_FILE, "sign -> base64encode -> encrypt -> base64encode");
		
		System.out.println("Encrypted data length " + encrypted.length + "b\nEncryption complete.");
		
	}

}
