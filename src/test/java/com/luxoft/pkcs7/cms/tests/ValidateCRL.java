package com.luxoft.pkcs7.cms.tests;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Principal;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ValidateCRL {

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		System.setProperty("http.proxyHost", "localhost");
		System.setProperty("http.proxyPort", "9080");
		
		Security.setProperty("ocsp.enable", "true");
        
        System.setProperty("com.sun.security.enableCRLDP", "true");
        System.setProperty("com.ibm.security.enableCRLDP", "true");
        boolean enable_revokation = true;
	  
	  
        // уникальное имя сертификата открытого ключа
        final String aliasEndCert = "piv";
        
        
        
       //инициализация хранилища доверенных сертификатов и ключевого носителя
        final KeyStore keyStore = KeyStore.getInstance("HDImageStore");

        // загрузка содержимого хранилища (предполагается, что хранилище,
        // проинициализированное именем STORE_TYPE существует) и содержимого
        // ключевого носителя
        keyStore.load(new FileInputStream("C:\\var\\CPROcsp\\certstore"), null);
        
        // чтение конечного сертификата (сертификата открытого ключа) с носителя
        // (предполагается, что сертификат такой сертификат существует на носителе)
        final X509Certificate certEnd = (X509Certificate) keyStore.getCertificate(aliasEndCert);
        certEnd.checkValidity();
        
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
        
        //Построение цепочки из прочитанных сертификатов, начиная с корневого сертификата
        //(с именем aliasRootCert) и заканчивая сертификатом открытого ключа (c именем aliasEndCert)

        // определение списка сертификатов, из которых
        // осуществляется построение цепочки
        final List<Certificate> certs = new ArrayList<Certificate>(3);
        //certs.add(certEnd);

        Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
        Enumeration<String> aliases = keyStore.aliases();
        while(aliases.hasMoreElements()) {
        	String alias = aliases.nextElement();
        	if (!alias.startsWith("cacer")) {
        		continue;
        	}
        	Certificate c = keyStore.getCertificate(alias);
        	try {
        		((X509Certificate)c).checkValidity();
        	} catch (java.security.cert.CertificateExpiredException cee) {
        		System.out.println(alias + " expired " + cee.getMessage());
        		continue;
        	}
	        // определение корневого сертификата (с которого начинается построение
	        // цепочки)
        	//if (alias.equals("cacer5")) {
        	TrustAnchor anchor = new TrustAnchor((X509Certificate) c, null);
        	trustAnchors.add(anchor);
        	//certs.add(c);
        	System.out.println("Cert trusted: " + alias);
        	//}
        }

        // определение параметров специального хранилища
        // сертификатов, в которое записываются все используемые
        // в построении цепочки сертификаты
        final CollectionCertStoreParameters par =
                new CollectionCertStoreParameters(certs);

        // создание специального хранилища сертификатов на основе
        // параметров, определенных списком сертификатов
        final CertStore store = CertStore.getInstance("Collection", par);

        // инициализация объекта построения цепочки сертификатов
        final CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
        //или для совместимости с КриптоПро УЦ
        //CertPathBuilder cpb = CertPathBuilder.getInstance("CPPKIX");

        // инициализация параметров построения цепочки сертификатов
        final PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, new X509CertSelector());

        // добавление к параметрам сертификатов, из которых
        // будет строиться цепочка
        params.addCertStore(store);

        // инициализация объекта выборки сертификата, которым
        // заканчивается построение цепочки
        final X509CertSelector selector = new X509CertSelector();

        // определение сертификата, которым
        // заканчивается построение цепочки
        selector.setCertificate((X509Certificate) certEnd);

        params.setTargetCertConstraints(selector);
        
        params.setSigProvider("JCP");
        
        params.setRevocationEnabled(enable_revokation);
        
        

        // построение цепочки сертификатов
        final PKIXCertPathBuilderResult res = (PKIXCertPathBuilderResult) cpb.build(params);
        System.out.println(res);
        CertPath cp = res.getCertPath();
        System.out.println("CertPath size : " + cp.getCertificates().size());
        /* Проверка построенной цепочки сертификатов */

        // инициализация объекта проверки цепочки сертификатов
        final CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        //или для совместимости с КриптоПро УЦ
        //CertPathValidator validator = CertPathValidator.getInstance("CPPKIX");
        

        // проверка цепочки сертификатов
        final CertPathValidatorResult val_res = validator.validate(res.getCertPath(), params);

        // вывод результата проверки в строком виде
        System.out.println("\n\n\n");
        System.out.println(val_res.toString());
	    
	}
	
}
