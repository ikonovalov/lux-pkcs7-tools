package com.luxoft.pkcs7.cms.signalcom;

import java.io.FileOutputStream;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.Iterator;
import java.util.Set;

import ru.signalcom.crypto.cms.ProductInfo;
import ru.signalcom.crypto.provider.SignalCOMProvider;

import com.luxoft.pki.tools.CryptoUtils;
import com.luxoft.pki.tools.PKIXUtils;
import com.luxoft.pki.tools.SignalComCryptoUtils;

public class SignalDecryptAndCheck {

	public static void main(String[] args) throws Exception {
		
		Security.addProvider(new SignalCOMProvider());
		
		System.setProperty("http.proxyHost", "192.168.5.15");
		System.setProperty("http.proxyPort", "8080"); 
		
		PKIXUtils.enableCRLDP(true);
		PKIXUtils.enableOCSP(true);
		
		System.out.println("===============================================================");

		/*String keystoreFile = "C:/developer/lib/signalcom/scjcms-sdk-1.2.7/scjcms-sdk-1.2.7/test/pse/keystore.p12";
		String password = "111111";
		String[] signer = new String[]{"ecgost-cp"};
		String[] recipient = new String[]{"ecgost-cp"};*/
		
		String keystoreFile = "C:/developer/temp/bak_contact/Key#2_2011/store.pfx";
		String password = "123";
		String[] signer = new String[]{"KEY1"};
		String[] recipient = new String[]{"KEY1"};
		
		byte[] sourceData = keystoreFile.getBytes();
		
		CryptoUtils scutils = new SignalComCryptoUtils(keystoreFile, password); 
		scutils.signer(signer).recipients(recipient);

		
		byte[] encrypted = scutils.actions(sourceData, null, CryptoUtils.ACTION_SIGN, CryptoUtils.ACTION_ENCRYPT);


		scutils = new SignalComCryptoUtils(keystoreFile, password); 
		scutils.withVerificationOptions(CryptoUtils.OPT_STORED_CERT_ONLY);
		byte[] buffer = scutils.actions(encrypted, null, CryptoUtils.ACTION_DECRYPT, CryptoUtils.ACTION_VERIFY, CryptoUtils.ACTION_DETACH);
	
		System.out.println("Result "  + new String(buffer)) ;
		
	}

}
