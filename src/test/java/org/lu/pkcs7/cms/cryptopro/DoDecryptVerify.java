package org.lu.pkcs7.cms.cryptopro;

import java.io.File;
import java.io.FileInputStream;

import org.lu.pki.tools.CryptoProCryptoUtils;
import org.lu.pki.tools.CryptoUtils;

public class DoDecryptVerify {

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		
		System.setProperty("http.proxyHost", "192.168.5.15");
		System.setProperty("http.proxyPort", "8080");  
		
		File fEncrypted = new File(DoSignEncrypt.ENCRYPTED_FILE); 
		byte[] buffer = new byte[(int) fEncrypted.length()];
		new FileInputStream(fEncrypted).read(buffer);
		
		CryptoUtils cputilsD = new CryptoProCryptoUtils("C:/Users/user1/Documents/444", "123"); 
		cputilsD.withVerificationOptions("STORED_CERT_ONLY, SKIP_SELFSIGNED_CERT");
		byte[] decrypted = cputilsD.actions(buffer, null,  "decrypt -> verify -> detach");
		
		System.out.println(new String(decrypted));

	}

}
