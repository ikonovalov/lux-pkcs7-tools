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
		
		System.setProperty("http.proxyHost", "localhost");
		System.setProperty("http.proxyPort", "8081");  
		
		PKIXUtils.enableCRLDP(true);
		PKIXUtils.enableOCSP(true);
		
		byte[] sourceData = "bu-bu777888-000-111-222".getBytes();
		
		CryptoUtils cputilsE = new CryptoProCryptoUtils("C:/Users/user1/Documents/444", "123"); 
		
		cputilsE.signer("luxoft-test2","st1", "luxoft-test1").recipients("st2", "barankevich2012.cer", "pivsaeva_2012_tcs");
		
		byte[] encrypted = cputilsE.actions(sourceData, "C:\\developer\\temp\\cryptopro_enveloped.p7m", CryptoUtils.ACTION_SIGN, CryptoUtils.ACTION_ENCRYPT);

		encrypted = CryptoUtils.convertDERtoBASE64(encrypted);
		
		CryptoUtils cputilsD = new CryptoProCryptoUtils("C:/Users/user1/Documents/444", "123"); 
		cputilsD.withVerificationOptions(CryptoUtils.OPT_STRONG_POLICY | CryptoUtils.OPT_SKIP_SELFSIGNED_CERT);
		byte[] decrypted = cputilsD.actions(encrypted, null,  CryptoUtils.ACTION_DECRYPT, CryptoUtils.ACTION_VERIFY, CryptoUtils.ACTION_DETACH);
		
		System.out.println(new String(decrypted));
	}

}
