package com.luxoft.pkcs7.cms.signalcom;

import java.io.FileOutputStream;
import java.security.Security;

import ru.signalcom.crypto.cms.ProductInfo;
import ru.signalcom.crypto.provider.SignalCOMProvider;

import com.luxoft.pki.tools.PKIXUtils;
import com.luxoft.pki.tools.SignalComCryptoUtils;

public class SignalDecryptAndCheck {

	public static void main(String[] args) throws Exception {
		Security.addProvider(new SignalCOMProvider());
		
		System.setProperty("http.proxyHost", "192.168.5.15");
		System.setProperty("http.proxyPort", "8080");  
		
		PKIXUtils.enableCRLDP(true);
		PKIXUtils.enableOCSP(true);
		
		System.out.println(new ProductInfo());
		String keystoreFile = "C:/developer/lib/signalcom/scjcms-sdk-1.2.7/scjcms-sdk-1.2.7/test/pse/keystore.p12";
		String password = "111111";
		
		SignalComCryptoUtils scutils = new SignalComCryptoUtils(keystoreFile, password); 
		scutils.signer("ecgost-cp").recipients("ecgost-cp");
		
		byte[] signedData = scutils.signAttached(keystoreFile.getBytes());
		System.out.print("Signed");
		
		FileOutputStream fos1 = new FileOutputStream("C:/developer/temp/signalcom_enveloped.p7s");
		fos1.write(signedData);
		fos1.close();
		
		byte[] encrypted = scutils.encrypt(signedData);
		System.out.print(" -> Encrypted");
		
		byte[] decrypted = scutils.decrypt(encrypted);
		System.out.print(" -> Decrypt");
		
		scutils.verify(decrypted);
		System.out.print(" -> Verify");
		
		byte[] detached = scutils.detach(decrypted);
		System.out.println(" -> Detach");
		
		FileOutputStream fos2 = new FileOutputStream("C:/developer/temp/signalcom_enveloped.p7m");
		fos2.write(encrypted);
		fos2.close();
		
		System.out.println("Result "  + new String(detached)) ;
		
	}

}
