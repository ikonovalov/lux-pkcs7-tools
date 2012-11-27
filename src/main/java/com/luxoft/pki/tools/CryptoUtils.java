package com.luxoft.pki.tools;

/**
 * 
 * @author Igor Konovalov ikonovalov@luxoft.com
 *
 */
public interface CryptoUtils {
	
	public byte[] decrypt(byte[] ciphertext) throws Exception;
	
	public byte[] detach(byte[] signed) throws Exception;
	
	public byte[] encrypt(byte[] plain) throws Exception;
	
	public CryptoUtils recipients(String... recipientsAliases) throws Exception;
	
	public byte[] signAttached(byte[] data) throws Exception;
	
	public SignalComCryptoUtils signer(String... signerAliases) throws Exception;
	
	public void verify(byte[] signed) throws Exception;

}
