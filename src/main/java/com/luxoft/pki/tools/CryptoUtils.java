package com.luxoft.pki.tools;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;

/**
 * 
 * @author Igor Konovalov ikonovalov@luxoft.com
 *
 */
public abstract class CryptoUtils {
	
	private KeyStore keyStore = null;
	
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
	
	protected  X509Certificate getCertificateFromStore(String alias) throws KeyStoreException {
		X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
		if (cert == null) {
			throw new KeyStoreException("Certificate for alias '" + alias + "' not found");
		}
		return cert;
	}
	
	protected PrivateKey getKeyFromStore(String alias, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
		return (PrivateKey) getKeyStore().getKey(alias, password);
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

}
