package com.luxoft.pki.tools;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import ru.CryptoPro.JCP.ASN.CertificateExtensions.SubjectKeyIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.IssuerAndSerialNumber;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignerIdentifier;

/**
 * 
 * @author Igor Konovalov ikonovalov@luxoft.com
 *
 */
@SuppressWarnings("restriction")
public abstract class CryptoUtils {
	
	public static final String SUBJECT_KEY_IDENTEFER_OID = "2.5.29.14";
	
	private KeyStore keyStore = null;
	
	private int verificationOptions = 0;
	
	public final static int OPT_ALL_FLAGS_DOWN  = 0;
	
	public final static int OPT_STORED_CERT_ONLY = 1;
	
	public final static int OPT_ALLOW_SELFSIGNED_CERT = 8;
	
	public final static int OPT_SKIP_SELFSIGNED_CERT = 16;
	
	public final static int OPT_DISABLE_CERT_VALIDATION = 32;
	
	public final static int OPT_STRONG_POLICY = OPT_STORED_CERT_ONLY;
	
	// --- ABSTRACT PART -------------------------------------------
	public abstract byte[] decrypt(byte[] ciphertext) throws Exception;
	
	public abstract byte[] detach(byte[] signed) throws Exception;
	
	public abstract byte[] encrypt(byte[] plain) throws Exception;
	
	/**
	 * Добавление списка получателей сообщения. Используется в RecipientInfo и при генерации ключа сограсования.
	 * @param recipientsAliases - массив алиасов сертификатов получателей.
	 * @return
	 * @throws Exception
	 */
	public abstract CryptoUtils recipients(String... recipientsAliases) throws Exception;
	
	public abstract byte[] signAttached(byte[] data) throws Exception;
	
	/**
	 * Добавление подписчиков сообщения. (По списку выбираются PrivateKey из хранилища и подписывают сообщение)
	 * @param signerAliases - массив алиасов подписчиков
	 * @return
	 * @throws Exception
	 */
	public abstract CryptoUtils signer(String... signerAliases) throws Exception;
	
	public abstract void verify(byte[] signed) throws Exception;
	
	// =============================================================
	
	public final int withVerificationOptions(int... flags) {
		for (int f : flags) {
			this.verificationOptions |= f;
		}
		return this.verificationOptions;
	}
	
	protected final boolean isFlagSet(int flagbitN) {
		return (verificationOptions & flagbitN) == flagbitN;
	}
	
	protected final boolean isFlagNotSet(int flagbitN) {
		return !isFlagSet(flagbitN);
	}
	
	/**
	 * 
	 * @param alias
	 * @return
	 * @throws KeyStoreException - если сертификат не найден или проиче проблемы с хранилищем.
	 */
	protected  X509Certificate getCertificateFromStore(String alias) throws KeyStoreException {
		if (alias == null) {
			return null;
		}
		X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
		if (cert == null) {
			throw new KeyStoreException("Certificate for alias '" + alias + "' not found");
		}
		return cert;
	}
	
	protected PrivateKey getKeyFromStore(String alias, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
		if (alias == null) {
			return null;
		} else {
			return (PrivateKey) getKeyStore().getKey(alias, password);
		}
	}

	/**
	 * Получение текущего хранилища ключей и сертификатов X509
	 * @return KeyStore
	 */
	protected final KeyStore getKeyStore() {
		return keyStore;
	}
	
	/**
	 * Установка хранилища сертификатов. Для инстанса выполняется только одина раз.
	 * @param keyStore
	 */
	protected final void setKeyStore(KeyStore keyStore) {
		if (this.keyStore == null) {
			this.keyStore = keyStore;
		} else {
			throw new RuntimeException("KeyStore already set");
		}
	}
	
	/**
	 * Вызгузка всех сертификатов в хранилище как CertStore
	 * @return
	 * @throws KeyStoreException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchAlgorithmException
	 */
	protected CertStore getAllCertificateFromStore() throws KeyStoreException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		List<X509Certificate> certs = new ArrayList<X509Certificate>();
		Enumeration<String> aliasesEnum = getKeyStore().aliases();
		while(aliasesEnum.hasMoreElements()) {
			String currentAlias = aliasesEnum.nextElement();
			X509Certificate cert = getCertificateFromStore(currentAlias);
			certs.add(cert);
		}
		return PKIXUtils.createCertStoreFromList(certs);
	}
	
	/**
	 * Поиск в хранилище KeyStore сертификата по серийному номеру
	 * @param serialNumber
	 * @return null - если сертификат не найден.
	 * @throws KeyStoreException
	 */
	protected final String lookupKeyStoreBySerialNumber(BigInteger serialNumber) throws KeyStoreException {
		String res = null;
		Enumeration<String> aliasesEnum = getKeyStore().aliases();
		while(aliasesEnum.hasMoreElements()) {
			String currentAlias = aliasesEnum.nextElement();
			X509Certificate cer = getCertificateFromStore(currentAlias);
			if (cer.getSerialNumber().equals(serialNumber) && getKeyStore().isKeyEntry(currentAlias)) {
				res = currentAlias;
				break;
			}
		}
		return res;
	}
	
	/**
	 * Поиск в хранилище KeyStore сертификата по SubjectKeyIdentefer
	 * @param ski
	 * @return null - если сертификат не найден.
	 * @throws KeyStoreException
	 */
	protected final String lookupKeyStoreBySubjectKeyIdentefer(byte[] ski) throws KeyStoreException {
		String res = null;
		Enumeration<String> aliasesEnum = getKeyStore().aliases();
		while(aliasesEnum.hasMoreElements()) {
			String currentAlias = aliasesEnum.nextElement();
			X509Certificate cer = getCertificateFromStore(currentAlias);
			byte[] currentSKI = cer.getExtensionValue(SUBJECT_KEY_IDENTEFER_OID);
			if (Arrays.equals(ski, currentSKI) && getKeyStore().isKeyEntry(currentAlias)) {
				res = currentAlias;
				break;
			}
		}
		return res;
	}
	
	 /**
     * Поиск сертификата.
     * @param stores хранилища сертификатов.
     * @param issuer имя издателя.
     * @param serial серийный номер.
     * @return сертификат.
     * @throws CertStoreException
     */
	protected final X509Certificate lookupCertificateBySerialNumber(final List<CertStore> stores, final X500Principal issuer, final BigInteger serial) throws CertStoreException {

        X509CertSelector csel = new X509CertSelector();
        csel.setIssuer(issuer);
        csel.setSerialNumber(serial);

        return lookupCertificate(stores, csel);
    }
	
	/**
	 * Поиск сертификата по SubjectKeyIdentefer
	 * @param stores
	 * @param subjectKeyIdentefer
	 * @return
	 * @throws CertStoreException
	 */
	protected final X509Certificate lookupCertificateBySubjectKeyIdentefer(final List<CertStore> stores, final byte[] subjectKeyIdentefer) throws CertStoreException {

        X509CertSelector csel = new X509CertSelector();
        csel.setSubjectKeyIdentifier(subjectKeyIdentefer);
        return lookupCertificate(stores, csel);
    }
	
	/**
	 * Поиск в списке CertStore-ов по селектору
	 * @param stores List<CertStore>
	 * @param selector - настроенный X509CertSelector
	 * @return null - если сертификат не найден
	 * @throws CertStoreException
	 */
	protected X509Certificate lookupCertificate(final List<CertStore> stores, final X509CertSelector selector) throws CertStoreException {
        Iterator<CertStore> it = stores.iterator();
        while (it.hasNext()) {
            CertStore store = it.next();
            Collection col = store.getCertificates(selector);
            if (!col.isEmpty()) {
                return (X509Certificate) col.iterator().next();
            }
        }
        return null;
    }
	
	protected static String signerIdentifierToString(ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignerIdentifier sid) {
		StringBuilder sb = new StringBuilder();

		if (sid.getChoiceID() == SignerIdentifier._ISSUERANDSERIALNUMBER) {
			IssuerAndSerialNumber issuerAndSerialNumber = (IssuerAndSerialNumber) sid.getElement();
			BigInteger serialNumber = issuerAndSerialNumber.serialNumber.value;				
			sb.append("SignerIdentifier: SerialNumber=").append(serialNumber);  
			
		} else if (sid.getChoiceID() == SignerIdentifier._SUBJECTKEYIDENTIFIER) {
			SubjectKeyIdentifier subjectKeyIdentifier = (SubjectKeyIdentifier) sid.getElement();
			byte[] ski = subjectKeyIdentifier.value;
			sb.append("SignerIdentifier: SubjectKeyIdentefer = ");
			for (byte skib : ski) {
				sb.append(String.format("%02X ", skib));
			}
		}
		return sb.toString();
	}

}
