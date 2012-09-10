/**
 * $RCSfile: CMSDecrypt.java,v $
 * version $Revision: 1.5 $
 * created 28.05.2008 10:26:51 by kunina
 * last modified $Date: 2009/04/22 12:52:44 $ by $Author: kunina $
 * (C) ООО Крипто-Про 2004-2008.
 *
 * Программный код, содержащийся в этом файле, предназначен
 * для целей обучения. Может быть скопирован или модифицирован
 * при условии сохранения абзацев с указанием авторства и прав.
 *
 * Данный код не может быть непосредственно использован
 * для защиты информации. Компания Крипто-Про не несет никакой
 * ответственности за функционирование этого кода.
 */
package com.luxoft.pkcs7.cms.tests;

import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import ru.CryptoPro.Crypto.spec.GostCipherSpec;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.ContentInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.EnvelopedData;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.KeyTransRecipientInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.RecipientInfo;
import ru.CryptoPro.JCP.ASN.Gost28147_89_EncryptionSyntax.Gost28147_89_Parameters;
import ru.CryptoPro.JCP.ASN.GostR3410_EncryptionSyntax.GostR3410_KeyTransport;
import ru.CryptoPro.JCP.params.OID;
import ru.CryptoPro.JCP.tools.Array;

import com.objsys.asn1j.runtime.Asn1BerDecodeBuffer;
import com.objsys.asn1j.runtime.Asn1BerEncodeBuffer;

import static com.luxoft.pkcs7.cms.tests.CLIParser.*;

/**
 * Decrypt message.
 *
 * @author Copyright 2004-2009 Crypto-Pro. All rights reserved.
 * @.Version
 */
public class St3CMSDecrypt {

private static final String CMS_FILE_PATH = St2CMSSignAndEncrypt.CMS_FILE_PATH;
private static final String CIPHER_MODE = St2CMSSignAndEncrypt.CIPHER_MODE;

public static void main(String[] args) throws Exception {
	
	CLIParser cli = new CLIParser();
	cli.init(args);
	System.out.println(cli.toString());
	
    // cms-сообщение для расшифрования
	String encryptedFilePath = (cli.contains(ENCRYPTED_FILE) ? cli.getParam(ENCRYPTED_FILE) : CMS_FILE_PATH);
	System.out.println("File for encryption: " + encryptedFilePath);
    final byte[] buffer = Array.readFile(encryptedFilePath);
    
    //разбор CMS-сообщения
    Asn1BerDecodeBuffer dbuf = new Asn1BerDecodeBuffer(buffer);
    final ContentInfo all = new ContentInfo();
    all.decode(dbuf);
    dbuf.reset();
    final EnvelopedData cms = (EnvelopedData) all.content;
    
    KeyTransRecipientInfo keytrans = new KeyTransRecipientInfo();
    if (cms.recipientInfos.elements[0].getChoiceID() == RecipientInfo._KTRI) {
        keytrans = (KeyTransRecipientInfo) (cms.recipientInfos.elements[0].getElement());
    }
    
    final Asn1BerEncodeBuffer ebuf = new Asn1BerEncodeBuffer();
    dbuf = new Asn1BerDecodeBuffer(keytrans.encryptedKey.value);
    
    final GostR3410_KeyTransport encrKey = new GostR3410_KeyTransport();
    encrKey.decode(dbuf);
    dbuf.reset();
    
    encrKey.sessionEncryptedKey.encode(ebuf);
    final byte[] wrapKey = ebuf.getMsgCopy();
    ebuf.reset();
    
    encrKey.transportParameters.ephemeralPublicKey.encode(ebuf);
    final byte[] encodedPub = ebuf.getMsgCopy();
    ebuf.reset();
    
    final byte[] sv = encrKey.transportParameters.ukm.value;
    final Gost28147_89_Parameters params = (Gost28147_89_Parameters) cms.encryptedContentInfo.contentEncryptionAlgorithm.parameters;
    final byte[] iv = params.iv.value;
    final OID cipherOID = new OID(params.encryptionParamSet.value);
    final byte[] text = cms.encryptedContentInfo.encryptedContent.value;

    //Загрузка хранилища
    final KeyStore hdImageStore = KeyStore.getInstance(JCP.HD_STORE_NAME);
    hdImageStore.load(null, null);
    //получатель - закрытый ключ
    String containerAlias = (cli.contains(CONTAINER_ALIAS) ? cli.getParam(CONTAINER_ALIAS) : "Tinkoff");
    System.out.println("Container alias: " + containerAlias);
    char[] containerPassword = (cli.contains(CONTAINER_PASSWORD) ? cli.getParam(CONTAINER_PASSWORD).toCharArray() : null);
    System.out.println("Use container password? " + (containerPassword != null));
    final PrivateKey responderKey = (PrivateKey) hdImageStore.getKey(containerAlias, containerPassword);
    if (responderKey == null) {
    	throw new IllegalArgumentException("Private key not found for " + containerAlias);
    }
    System.out.println("Tinkoff Private key alg: " + responderKey.getAlgorithm());

    //отправитель - открытый ключ из cms
    final X509EncodedKeySpec pspec = new X509EncodedKeySpec(encodedPub);
    final KeyFactory kf = KeyFactory.getInstance(JCP.GOST_DH_NAME);
    final PublicKey senderPublic = kf.generatePublic(pspec);
    System.out.println("Rapida Public key alg: " + senderPublic.getAlgorithm());
    
    // выработка ключа согласования получателем
    final KeyAgreement responderKeyAgree = KeyAgreement.getInstance(JCP.GOST_DH_NAME);
    responderKeyAgree.init(responderKey, new IvParameterSpec(sv), null);
    responderKeyAgree.doPhase(senderPublic, true);
    final SecretKey responderSecret = responderKeyAgree
            .generateSecret("GOST28147");

    // Расшифрование симметричного ключа.
    final Cipher cipher = Cipher.getInstance(CIPHER_MODE);
    cipher.init(Cipher.UNWRAP_MODE, responderSecret, (SecureRandom) null);
    final SecretKey simmKey = (SecretKey) cipher
            .unwrap(wrapKey, null, Cipher.SECRET_KEY);

    // Расшифрование текста на симметричном ключе.
    final GostCipherSpec spec = new GostCipherSpec(iv, cipherOID);
    cipher.init(Cipher.DECRYPT_MODE, simmKey, spec, null); 
    byte[] result = cipher.doFinal(text, 0, text.length);
    //System.out.println(new String(result));
    // if result = signedData ($CMS_FILE)
    System.out.println("<------------------------- SIGNED DATA CONTAINED START----------------------->");
    System.out.println(new String(result));
    System.out.println("<------------------------- SIGNED DATA CONTAINED END------------------------->");
    try {
    	St4CMSVerify.cmsVerify(result, null, null, args);
    } catch (Exception e) {
    	result = javax.xml.bind.DatatypeConverter.parseBase64Binary(new String(result));
    	St4CMSVerify.cmsVerify(result, null, null, args);
    }
    
    
}
}
