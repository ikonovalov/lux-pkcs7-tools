package org.lu.pkcs7.cms.signalcom;

import java.io.File;
import java.io.FileInputStream;
import java.security.Security;

import org.lu.pki.tools.CryptoUtils;
import org.lu.pki.tools.PKIXUtils;
import org.lu.pki.tools.SignalComCryptoUtils;

import ru.CryptoPro.JCP.tools.Array;
import ru.signalcom.crypto.provider.SignalCOMProvider;


public class SignalDecryptAndCheck {

	public static void main(String[] args) throws Exception {
		
		Security.addProvider(new SignalCOMProvider());
		Security.addProvider(new SignalCOMProvider());
		
		
		System.setProperty("http.proxyHost", "192.168.5.15");
		System.setProperty("http.proxyPort", "8080"); 
		
		PKIXUtils.switchOnOCSPandCRLDP();

		System.out.println("===============================================================");

		/*String keystoreFile = "C:/developer/lib/signalcom/scjcms-sdk-1.2.7/scjcms-sdk-1.2.7/test/pse/keystore.p12";
		String password = "111111";
		String[] signer = new String[]{"ecgost-cp"};
		String[] recipient = new String[]{"ecgost-cp"};*/
		
		String keystoreFile = "C:/developer/temp/bak_contact/Key#2_2011/store.pfx";
		String password = "123";
		String[] signer = new String[]{"cert_16464"};
		String[] recipient = new String[]{"cert_16464", "cert_3955"};
		
		String folder = "C:/developer/temp/";
		
		byte[] sourceData = keystoreFile.getBytes();
		
		CryptoUtils scutils = new SignalComCryptoUtils(keystoreFile, password); 
		scutils.signer(signer).recipients(recipient);
		byte[] encrypted = scutils.actions(sourceData, folder + "sygnal_test.encrypted2", "sign -> encrypt");

		encrypted = Array.readFile(folder + "sygnal_test.encrypted2");
		
		File f = new File(folder + "sygnal_test.encrypted2");
		FileInputStream fis = new FileInputStream(f);
		byte[] buffer = new byte[(int) f.length()];
		fis.read(buffer);
		encrypted = buffer;
		
		scutils = new SignalComCryptoUtils(keystoreFile, password); 
		scutils.withVerificationOptions(CryptoUtils.OPT_STORED_CERT_ONLY);
		//byte[] buffer = scutils.actions(encrypted, null, CryptoUtils.ACTION_DECRYPT, CryptoUtils.ACTION_VERIFY, CryptoUtils.ACTION_DETACH);
		buffer = scutils.actions(encrypted, null, "decrypt -> verify -> detach");
	
		System.out.println("Result "  + new String(buffer)) ;
		
	}

}
