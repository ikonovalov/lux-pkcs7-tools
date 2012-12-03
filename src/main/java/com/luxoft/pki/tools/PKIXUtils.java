package com.luxoft.pki.tools;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;

/**
 * 
 * @author Igor Konovalov ikonovalov@luxoft.com
 * 
 */
public class PKIXUtils {

	private static final String AUTHORITY_INFO_ACCESS_OID = "1.3.6.1.5.5.7.1.1";

	private static final Logger LOG = Logger.getLogger(CertificateVerifier.class.getName());

	private static final String COM_IBM_SECURITY_ENABLE_CRLDP = "com.ibm.security.enableCRLDP";
	private static final String COM_SUN_SECURITY_ENABLE_CRLDP = "com.sun.security.enableCRLDP";
	private static final String OCSP_ENABLE = "ocsp.enable";
	private static final String CRLDP_EXTENSION_OID = "2.5.29.31";

	/**
	 * Extracts all CRL distribution point URLs from the
	 * "CRL Distribution Point" extension in a X.509 certificate. If CRL
	 * distribution point extension is unavailable, returns an empty list.
	 */
	public static List<String> getCrlDistributionPoints(X509Certificate cert) throws CertificateParsingException, IOException {
		byte[] crldpExt = cert.getExtensionValue(CRLDP_EXTENSION_OID);
		if (crldpExt == null) {
			List<String> emptyList = new ArrayList<String>();
			return emptyList;
		}
		ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crldpExt));
		DERObject derObjCrlDP = oAsnInStream.readObject();
		DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
		byte[] crldpExtOctets = dosCrlDP.getOctets();
		ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
		DERObject derObj2 = oAsnInStream2.readObject();
		CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);
		List<String> crlUrls = new ArrayList<String>(5);
		for (DistributionPoint dp : distPoint.getDistributionPoints()) {
			DistributionPointName dpn = dp.getDistributionPoint();
			// Look for URIs in fullName
			if (dpn != null) {
				if (dpn.getType() == DistributionPointName.FULL_NAME) {
					GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
					// Look for an URI
					for (int j = 0; j < genNames.length; j++) {
						if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
							String url = DERIA5String.getInstance(genNames[j].getName()).getString();
							crlUrls.add(url);
						}
					}
				}
			}
		}
		return crlUrls;
	}

	/**
	 * Получние информации об OCSP
	 * 
	 * @param cert
	 *            X509Certificate, который возможно содержит адрес OCSP
	 * @return List<String> of OSCP URLs
	 */
	public static List<String> getAuthorityInformationAccess(X509Certificate cert) {
		List<String> ocspLocationUrls = new ArrayList<String>();
		byte[] value = cert.getExtensionValue(AUTHORITY_INFO_ACCESS_OID);
		if (value == null) {
			return ocspLocationUrls; // extension unavailable
		}
		AuthorityInformationAccess authorityInformationAccess;
		try {
			DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(value)).readObject());
			authorityInformationAccess = new AuthorityInformationAccess((ASN1Sequence) new ASN1InputStream(oct.getOctets()).readObject());
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		}

		AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
		if (accessDescriptions == null) {
			LOG.fine("accessDescriptions is null in " + cert.getSubjectDN().getName());
			return ocspLocationUrls;
		}

		for (AccessDescription accessDescription : accessDescriptions) {

			GeneralName gn = accessDescription.getAccessLocation();
			DERIA5String str = DERIA5String.getInstance(gn.getName());
			String accessLocation = str.getString();
			ocspLocationUrls.add(accessLocation);
		}
		return ocspLocationUrls;
	}

	/**
	 * Загрузка CRL через url
	 * @param crlURL
	 * @return
	 * @throws MalformedURLException
	 * @throws IOException
	 * @throws CertificateException
	 * @throws CRLException
	 */
	public static X509CRL downloadCRLFromWebDP(String crlURL) throws MalformedURLException, IOException, CertificateException, CRLException {
		URL url = new URL(crlURL);
		InputStream crlStream = url.openStream();
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509CRL crl = (X509CRL) cf.generateCRL(crlStream);
			return crl;
		} finally {
			crlStream.close();
		}
	}

	/**
	 * Search given certificate in given key store.
	 * 
	 * @param cert
	 *            - certificate for search
	 * @param keyStore
	 *            - key store that will be used for search in.
	 * @return true if key store contains given certificate
	 */
	public static boolean containsCertificateInStore(X509Certificate cert, KeyStore keyStore) {
		boolean res = false;
		BigInteger requestedSerialNumber = cert.getSerialNumber();
		Enumeration<String> aliasesSet;
		try {
			aliasesSet = keyStore.aliases();

			String aliasTmpValue = null;
			Certificate certificateTmpValue = null;
			X509Certificate x509CertTempValue = null;
			// iterate over all certificates (X509 only) in key store
			while (aliasesSet.hasMoreElements()) {
				aliasTmpValue = aliasesSet.nextElement();
				certificateTmpValue = keyStore.getCertificate(aliasTmpValue);
				if (!isX509Certificate(certificateTmpValue)) { // don't accept
																// not X509
																// certificates
					continue;
				}
				x509CertTempValue = (X509Certificate) certificateTmpValue;
				if (x509CertTempValue.getSerialNumber().compareTo(requestedSerialNumber) == 0) { // we
																									// found
																									// this
																									// cert
																									// in
																									// store
																									// by
																									// serial
																									// number
					res = true;
					break;
				}
			}
		} catch (KeyStoreException e) {
			LOG.log(Level.SEVERE, "Key store access problem Method 'containsCertificateInStore' failed. " + e.getMessage(), e);
		}
		return res;
	}

	/**
	 * Check instanceof parameter for X509Certificate
	 * 
	 * @param certificateTmpValue
	 * @return true if this is X509Certificate
	 */
	public static boolean isX509Certificate(Certificate certificateTmpValue) {
		return certificateTmpValue instanceof X509Certificate;
	}

	public static void chechValidDate(Certificate c) throws CertificateExpiredException, CertificateNotYetValidException {
		((X509Certificate) c).checkValidity();
	}
	
	/**
	 * Получение всех сертификатов из хранилища.
	 * @param keyStore - хранилище ключей (и дополнительный certstore, если подключен)
	 * @return массив Certificate[]. Null недопустим, может быть массив нулевой длинны.
	 */
	public static Certificate[] getAllCertificatesInStore(KeyStore keyStore) {
		Certificate[] res = new Certificate[0];
		try {
			Enumeration<String> aliasesSet =  keyStore.aliases();
			List<Certificate> certList = new ArrayList<Certificate>();
			Certificate cert = null;
			while (aliasesSet.hasMoreElements()) {
				cert = keyStore.getCertificate(aliasesSet.nextElement());
				if (!isX509Certificate(cert)) {
					continue;
				}
				certList.add(cert);
			}
			if (certList.size() > 0) {
				res = certList.toArray(new Certificate[0]);
			}
		} catch (KeyStoreException e) {
			LOG.log(Level.SEVERE, "Key store access problem Method 'containsCertificateInStore' failed. " + e.getMessage(), e);
		}
		return res;
	}
	
	/**
	 * Checks whether given X.509 certificate is self-signed.
	 */
	public static boolean isSelfSigned(X509Certificate cert) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
		try {
			// Try to verify certificate signature with its own public key
			PublicKey key = cert.getPublicKey();
			cert.verify(key);	
			return true;
		} catch (SignatureException sigEx) {
			// Invalid signature --> not self-signed
			return false;
		} catch (InvalidKeyException keyEx) {
			// Invalid key --> not self-signed
			return false;
		}
	}

	public static boolean isIndirectCRL(X509CRL crl) {
		byte[] idp = crl.getExtensionValue("2.5.29.28"); // IssuingDistributionPoint
		boolean isIndirect = false;
		if (idp != null) {
			isIndirect = IssuingDistributionPoint.getInstance(idp).isIndirectCRL();
		}

		return isIndirect;
	}

	public static boolean isIbmCRLDPEnabled() {
		return "true".equals(System.getProperty(COM_IBM_SECURITY_ENABLE_CRLDP));
	}

	public static boolean isSunCRLDPEnabled() {
		return "true".equals(System.getProperty(COM_SUN_SECURITY_ENABLE_CRLDP));
	}

	public static boolean isOCSPEnabled() {
		return "true".equals(Security.getProperty(OCSP_ENABLE));
	}

	public static synchronized final void enableOCSP(boolean flag) {
		Security.setProperty(OCSP_ENABLE, String.valueOf(flag));
	}

	public static synchronized final void enableCRLDP(boolean flag) {
		System.setProperty(COM_SUN_SECURITY_ENABLE_CRLDP, String.valueOf(flag));
		System.setProperty(COM_IBM_SECURITY_ENABLE_CRLDP, String.valueOf(flag));
	}

	public static synchronized final void switchOnOCSPandCRLDP() {
		enableOCSP(true);
		enableCRLDP(true);
	}

	public static synchronized final void switchOffOCSPandCRLDP() {
		enableOCSP(false);
		enableCRLDP(false);
	}

	private static Boolean isIBMJ9 = null;
	
	public static synchronized boolean isIBMJ9() {
		return (isIBMJ9 == null ? isIBMJ9 = System.getProperty("java.vendor").toUpperCase().contains("IBM") : isIBMJ9);
	}
	
	public static CertStore createCertStoreFromList(List<X509Certificate> certs) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		return CertStore.getInstance("Collection", new CollectionCertStoreParameters(certs));
	}
}
