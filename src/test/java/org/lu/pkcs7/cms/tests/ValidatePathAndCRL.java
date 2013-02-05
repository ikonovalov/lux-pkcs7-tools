package org.lu.pkcs7.cms.tests;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Principal;
import java.security.cert.X509Certificate;

import org.lu.pki.tools.CertificateVerificationException;
import org.lu.pki.tools.CertificateVerificationResult;
import org.lu.pki.tools.CertificateVerifier;
import org.lu.pki.tools.CryptoProCryptoUtils;
import org.lu.pki.tools.CryptoUtils;
import org.lu.pki.tools.PKIXUtils;

import com.ibm.security.cert.CRSChecker;


public class ValidatePathAndCRL {
	
	public static void main(String[] args) throws Exception {
		
		System.out.println(PKIXUtils.isIBMJ9());
		
		System.setProperty("http.proxyHost", "localhost");
		System.setProperty("http.proxyPort", "8081");  

		
		//PKIXUtils.switchOnOCSPandCRLDP();
		CryptoUtils cu = new CryptoProCryptoUtils("C:\\var\\CPROcsp\\certstore", "123");
	  
        // уникальное имя сертификата открытого ключа
        final String aliasEndCert = "KorzhovMV";
        
       //инициализация хранилища доверенных сертификатов и ключевого носителя
        final KeyStore keyStore = KeyStore.getInstance("HDImageStore");

        // загрузка содержимого хранилища
        keyStore.load(new FileInputStream("C:\\var\\CPROcsp\\certstore"), "123".toCharArray());
        
        final X509Certificate certEnd = (X509Certificate) keyStore.getCertificate(aliasEndCert);
        
        
        
        System.out.println("Certificate " + certEnd.getSerialNumber() + " existed in store: " + PKIXUtils.containsCertificateInStore(certEnd, keyStore));
        
        printSubjectAndIssuerDN(certEnd);
        
        int ok = 0;
        int fail = 0;
       for (int z = 0; z < 1; z++) {
        
	        try {
	        	CertificateVerificationResult result = CertificateVerifier.verifyCertificate((X509Certificate)certEnd, keyStore, true, "JCP");
	        	//System.out.println(result);
	        	ok++;
			} catch (CertificateVerificationException e) {
				System.err.println(e.getMessage());
				fail++;
			}
	     
	        System.err.println("----------------------------------------------------------------------------");
       }
       System.out.println("Ok " + ok);
       System.out.println("Fail " + fail);
	}


	private static void printSubjectAndIssuerDN(final X509Certificate certEnd) {
		if (certEnd instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate)certEnd;

            // Get subject
            Principal principal = x509cert.getSubjectDN();
            String subjectDn = principal.getName();
            System.out.println("subjectDn: " + subjectDn);

            // Get issuer
            principal = x509cert.getIssuerDN();
            String issuerDn = principal.getName();
            System.out.println("getIssuerDN: " + issuerDn);
        }
	}

}
