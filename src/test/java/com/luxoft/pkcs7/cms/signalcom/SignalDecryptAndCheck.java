package com.luxoft.pkcs7.cms.signalcom;

import java.io.FileOutputStream;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.Enumeration;
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
		
		Provider[] providers = Security.getProviders();
		// CertPathValidator
		// CertPathBuilder
		for(Provider provider : providers) {
			Set<Service> serviceSet = provider.getServices();
			Iterator<Service> setIter = serviceSet.iterator();
			while(setIter.hasNext()) {
				Service service = setIter.next();
				if ("CertPathBuilder".equals(service.getType())) {
					System.out.println(provider.getName());
				}
			}
		}
		
		PKIXUtils.enableCRLDP(true);
		PKIXUtils.enableOCSP(true);
		
		System.out.println("===============================================================");
		
		System.out.println(new ProductInfo());
		String keystoreFile = "C:/developer/lib/signalcom/scjcms-sdk-1.2.7/scjcms-sdk-1.2.7/test/pse/keystore.p12";
		String password = "111111";
		
		CryptoUtils scutils = new SignalComCryptoUtils(keystoreFile, password); 
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
