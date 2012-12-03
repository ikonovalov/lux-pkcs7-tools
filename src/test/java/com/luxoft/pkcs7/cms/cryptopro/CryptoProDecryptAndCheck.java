package com.luxoft.pkcs7.cms.cryptopro;

import java.security.Provider;
import java.security.Security;

import ru.CryptoPro.JCP.tools.Array;
import ru.signalcom.crypto.provider.SignalCOMProvider;

import com.luxoft.pki.tools.CryptoProCryptoUtils;
import com.luxoft.pki.tools.CryptoUtils;
import com.luxoft.pki.tools.PKIXUtils;

public class CryptoProDecryptAndCheck {

	/**
	 * @param args
	 * @throws Exception 
	 */
	@SuppressWarnings("restriction")
	public static void main(String[] args) throws Exception {
		
		//Security.addProvider(new SignalCOMProvider());
		
		System.setProperty("http.proxyHost", "192.168.5.15");
		System.setProperty("http.proxyPort", "8080");  
		
		PKIXUtils.enableCRLDP(true);
		PKIXUtils.enableOCSP(true);
		
		
		Provider[] provArray = Security.getProviders();
		for (Provider provider : provArray) {
			System.out.println(provider.getName());
		}
		
		CryptoUtils cputils = new CryptoProCryptoUtils("C:/Users/user1/Documents/444", "123"); 
		
		
		cputils.signer("Rapida").recipients("st2", "barankevich2012.cer", "pivsaeva_2012_tcs");
		
		byte[] signedData = cputils.signAttached("bu-bu777888-000-111-222".getBytes());
		
		byte[] encrypted = cputils.encrypt(signedData);
		
		Array.writeFile("C:\\developer\\temp\\cryptopro_enveloped.p7m", encrypted);
		
		byte[] decrypted = cputils.decrypt(encrypted);
		
		cputils.withVerificationOptions(CryptoProCryptoUtils.OPT_STORED_CERT_ONLY);
		cputils.verify(decrypted);
		
		byte[] detached = cputils.detach(decrypted);
		System.out.println(new String(detached));
	}

}
