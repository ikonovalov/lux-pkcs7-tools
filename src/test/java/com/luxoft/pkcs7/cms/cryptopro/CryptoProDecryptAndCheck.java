package com.luxoft.pkcs7.cms.cryptopro;

import java.io.File;
import java.io.FileInputStream;

import com.luxoft.pki.tools.CryptoProCryptoUtils;
import com.luxoft.pki.tools.CryptoUtils;
import com.luxoft.pki.tools.PKIXUtils;

public class CryptoProDecryptAndCheck {

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		
		//Security.addProvider(new SignalCOMProvider());
		
		System.setProperty("http.proxyHost", "192.168.5.15");
		System.setProperty("http.proxyPort", "8080");  
		
		PKIXUtils.switchOnOCSPandCRLDP();
		
		byte[] sourceData = "bu-bu777888-000-111-222".getBytes();
		
		CryptoUtils cputilsE = new CryptoProCryptoUtils("C:/Users/user1/Documents/444", "123"); 
		
		cputilsE.signer("luxoft-test2","st1", "luxoft-test1").recipients("st2", "barankevich2012.cer", "pivsaeva_2012_tcs");
		
		byte[] encrypted = cputilsE.actions(sourceData, "C:\\developer\\temp\\cryptopro_enveloped.p7m", CryptoUtils.ACTION_SIGN, CryptoUtils.ACTION_ENCRYPT);
		
		//
		File f = new File("C:\\developer\\temp\\V002181221.p7m");
		FileInputStream fis = new FileInputStream(f);
		byte[] buffer = new byte[(int) f.length()];
		fis.read(buffer);
		fis.close();
		//

		encrypted = buffer;//CryptoUtils.convertDERtoBASE64(encrypted);
		
		CryptoUtils cputilsD = new CryptoProCryptoUtils("C:/Users/user1/Documents/444", "123"); 
		cputilsD.withVerificationOptions("STORED_CERT_ONLY, SKIP_SELFSIGNED_CERT");
		byte[] decrypted = cputilsD.actions(encrypted, null,  CryptoUtils.ACTION_DECRYPT, CryptoUtils.ACTION_VERIFY, CryptoUtils.ACTION_DETACH);
		
		System.out.println(new String(decrypted));
		
		System.out.println(cputilsD.getAllAliases().toString());
		System.out.println(cputilsD.getAllKeyAliases().toString());
		
		
		
	}

}
