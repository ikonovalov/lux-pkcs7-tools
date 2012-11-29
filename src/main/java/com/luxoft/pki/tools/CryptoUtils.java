package com.luxoft.pki.tools;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

/**
 * 
 * @author Igor Konovalov ikonovalov@luxoft.com
 *
 */
public abstract class CryptoUtils {
	
	private KeyStore keyStore;
	
	// --- ABSTRACT PART -------------------------------------------
	public abstract byte[] decrypt(byte[] ciphertext) throws Exception;
	
	public abstract byte[] detach(byte[] signed) throws Exception;
	
	public abstract byte[] encrypt(byte[] plain) throws Exception;
	
	public abstract CryptoUtils recipients(String... recipientsAliases) throws Exception;
	
	public abstract byte[] signAttached(byte[] data) throws Exception;
	
	public abstract CryptoUtils signer(String... signerAliases) throws Exception;
	
	public abstract void verify(byte[] signed) throws Exception;
	
	// =============================================================
	
	protected  X509Certificate getCertificateFromStore(String alias) throws KeyStoreException {
		X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
		if (cert == null) {
			throw new KeyStoreException("Certificate for alias '" + alias + "' not found");
		}
		return cert;
	}

	protected final KeyStore getKeyStore() {
		return keyStore;
	}

	protected final void setKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
	}

}
