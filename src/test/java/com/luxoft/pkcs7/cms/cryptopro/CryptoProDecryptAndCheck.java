package com.luxoft.pkcs7.cms.cryptopro;

import java.util.Random;

import ru.CryptoPro.JCP.params.AlgIdSpec;
import ru.CryptoPro.JCP.tools.Array;

import com.luxoft.pki.tools.CryptoProCryptoUtils;
import com.luxoft.pki.tools.CryptoUtils;
import com.luxoft.pki.tools.PKIXUtils;

public class CryptoProDecryptAndCheck {

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		Random rnd = new Random();
		System.out.println(rnd.nextInt(2));
		
		System.setProperty("http.proxyHost", "192.168.5.15");
		System.setProperty("http.proxyPort", "8080");  
		
		PKIXUtils.enableCRLDP(true);
		PKIXUtils.enableOCSP(true);
		
		CryptoUtils cputils = new CryptoProCryptoUtils("C:/Users/user1/Documents/444", "123"); 
		cputils.signer("st1", "st2").recipients("barankevich2012.cer", "st2", "pivsaeva_2012_tcs");
		byte[] signedData = cputils.signAttached("bu-bu777888-000-111-222".getBytes());
		byte[] encrypted = cputils.encrypt(signedData);
		
		Array.writeFile("C:\\developer\\temp\\cryptopro_enveloped.p7m", encrypted);
		
		System.out.println(AlgIdSpec.getDefaultCryptParams() == AlgIdSpec.getDefaultCryptParams());
	}

}
