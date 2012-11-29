package com.luxoft.pki.tools;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.x500.X500Principal;

import com.objsys.asn1j.runtime.Asn1BerDecodeBuffer;
import com.objsys.asn1j.runtime.Asn1BerEncodeBuffer;
import com.objsys.asn1j.runtime.Asn1Null;
import com.objsys.asn1j.runtime.Asn1ObjectIdentifier;
import com.objsys.asn1j.runtime.Asn1OctetString;

import ru.CryptoPro.Crypto.spec.GostCipherSpec;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.CMSVersion;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.CertificateChoices;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.CertificateSet;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.ContentEncryptionAlgorithmIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.ContentInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.ContentType;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.DigestAlgorithmIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.DigestAlgorithmIdentifiers;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.EncapsulatedContentInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.EncryptedContent;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.EncryptedContentInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.EncryptedKey;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.EnvelopedData;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.IssuerAndSerialNumber;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.KeyEncryptionAlgorithmIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.KeyTransRecipientInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.RecipientIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.RecipientInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.RecipientInfos;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignatureAlgorithmIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignatureValue;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignedData;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignerIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignerInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignerInfos;
import ru.CryptoPro.JCP.ASN.Gost28147_89_EncryptionSyntax.Gost28147_89_EncryptedKey;
import ru.CryptoPro.JCP.ASN.Gost28147_89_EncryptionSyntax.Gost28147_89_IV;
import ru.CryptoPro.JCP.ASN.Gost28147_89_EncryptionSyntax.Gost28147_89_ParamSet;
import ru.CryptoPro.JCP.ASN.Gost28147_89_EncryptionSyntax.Gost28147_89_Parameters;
import ru.CryptoPro.JCP.ASN.Gost28147_89_EncryptionSyntax._Gost28147_89_EncryptionSyntaxValues;
import ru.CryptoPro.JCP.ASN.GostR3410_EncryptionSyntax.GostR3410_KeyTransport;
import ru.CryptoPro.JCP.ASN.GostR3410_EncryptionSyntax.GostR3410_TransportParameters;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.AlgorithmIdentifier;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.CertificateSerialNumber;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Name;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.RDNSequence;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.SubjectPublicKeyInfo;
import ru.CryptoPro.JCP.params.AlgIdInterface;
import ru.CryptoPro.JCP.params.AlgIdSpec;
import ru.CryptoPro.JCP.params.OID;
import ru.CryptoPro.JCP.params.ParamsInterface;
import ru.CryptoPro.JCP.ASN.CertificateExtensions.SubjectKeyIdentifier;

/**
 * Если что-то непонятно, то лучше чем тут нигде http://www.ietf.org/rfc/rfc3852.txt
 * @author Igor Konovalov ikonovalov@luxoft.com
 * 
 */
@SuppressWarnings("restriction")
public class CryptoProCryptoUtils extends CryptoUtils {

	public static final String SUBJECT_KEY_IDENTEFER_OID = "2.5.29.14";

	public static final String ENVELOPED_DATA_OID = "1.2.840.113549.1.7.3";

	private static Logger LOG = Logger.getLogger(CryptoProCryptoUtils.class.getName());

	protected static final String CIPHER_MODE = "GOST28147/CFB/NoPadding";
	
	public static final String ENCAP_CONTENT_INDO_OID = "1.2.840.113549.1.7.1";
	
	public static final String SIGNED_DATA_OID = "1.2.840.113549.1.7.2";
	
	public static final String GOST28147_ALG = "GOST28147";
	
	/**
	 * Список подписывающих (отправителей).
	 */
	private final List<Signer> signers = new ArrayList<Signer>();
	
	/**
	 * Список адресатов.
	 */
    private final List<Recipient> recipients = new ArrayList<Recipient>();

	/**
	 * вектор усложнения ключа согласования
	 */
	private static final byte[] sv = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
	
	private final ParamsInterface paramss = AlgIdSpec.getDefaultCryptParams();

	private final String storeFile;
	private final char[] storePassword;

	public CryptoProCryptoUtils(final String keystoreFile, final String password) throws Exception {
		this.storeFile = keystoreFile;
		this.storePassword = password != null ? password.toCharArray() : null;

		init();
	}

	private void init() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore keyStore = KeyStore.getInstance(JCP.HD_STORE_NAME);
		if (this.storeFile != null) {
			InputStream in = new FileInputStream(new File(storeFile));
			keyStore.load(in, storePassword);
			in.close();
		} else {
			LOG.warning("Loading without cert store...");
			keyStore.load(null, null);
		}
		setKeyStore(keyStore);
	}

	private class Signer {
		private final PrivateKey key;
		private final X509Certificate cert;
		
		public Signer(PrivateKey key, X509Certificate cert) {
			super();
			this.key = key;
			this.cert = cert;
		}
		
		public final PrivateKey getKey() {
			return key;
		}
		
		public final X509Certificate getCert() {
			return cert;
		}
		
	}

	private class Recipient {
		private final X509Certificate cert;

		public Recipient(X509Certificate cert) {
			super();
			this.cert = cert;
		}

		public final X509Certificate getCert() {
			return cert;
		}
		
	}
	
	private X509Certificate addSignerToList(String alias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
		PrivateKey priv = getKeyFromStore(alias, storePassword);
		X509Certificate cert = getCertificateFromStore(alias);
		signers.add(new Signer(priv, cert));
		return cert;
	}
	
	private X509Certificate addRecipientToList(String recipient) throws KeyStoreException {
		X509Certificate cert = getCertificateFromStore(recipient);
		recipients.add(new Recipient(cert));
		return cert;
	}

	//===========================================================================================================
	
	public CryptoUtils signer(String... signerAliases) throws Exception {
		signers.clear();
		
    	if (signerAliases == null) { // ничего не делаем просто очищаем список
    		return this;
    	}
    	KeyStore keyStore = getKeyStore();
    	for (String signer : signerAliases) {
    		if (keyStore.isKeyEntry(signer)) {
    			addSignerToList(signer);
    		} else {
    			LOG.warning("Alias " + signer + " doesn't have private key and can't be a signer");
    		}
    	}
    	return this;
	}
	
	public CryptoUtils recipients(String... recipientsAliases) throws Exception {
		recipients.clear();
		
    	if (recipientsAliases != null) {	
	    	for (String recipient : recipientsAliases) {
	    		addRecipientToList(recipient);
	    	}
    	}
    	return this;
	}

	public byte[] encrypt(byte[] plain) throws Exception {
		
		// проверка исходных данных
		if (signers == null || signers.size() == 0) {
			throw new Exception("No one signer. Set at least one signer and try again.");
		}
		
		/*
		 *  EnvelopedData ::= SEQUENCE {
		 * version CMSVersion,
		 * originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
		 * recipientInfos RecipientInfos,
		 * encryptedContentInfo EncryptedContentInfo,
		 * unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
		 */
		
		final Cipher cipher = Cipher.getInstance(CIPHER_MODE); // my sweet enigma...
		
		// Генерирование симметричного ключа
		final SecretKey simm = generateRandomSimmetricKey();

		// Зашифрование текста на симметричном ключе.
		cipher.init(Cipher.ENCRYPT_MODE, simm, (SecureRandom) null);
		final byte[] initializationVector = cipher.getIV();
		final byte[] enctryptedData = cipher.doFinal(plain, 0, plain.length);
		
		// выбор случайного отправителя из списка подписчиков
		final Signer randomSigner = signers.get(new Random().nextInt(signers.size()));
		
		final int recipientListSize = recipients.size();
		
		// формирование CMS-сообщения
		final EnvelopedData envelopedData = new EnvelopedData();
		
		// EnvelopedData:version
		envelopedData.version = new CMSVersion(0);
		
		// EnvelopedData:recipientInfos
		envelopedData.recipientInfos = new RecipientInfos(recipientListSize);
		
		for (int z = 0; z < recipientListSize; z++) { // заполняем RecipientInfo[]
			final Recipient recipient = recipients.get(z);
			
			// генерирование ключа согласования
			final SecretKey agreementKey = generateDHAgreementKey(randomSigner.getKey(), recipient.getCert().getPublicKey());
			
			// Зашифрование симметричного ключа на ключе согласования отправителя
			cipher.init(Cipher.WRAP_MODE, agreementKey, (SecureRandom) null);
			final byte[] key = cipher.wrap(simm); // это ключик нужно положить в KTRI
			
			// Начинаем формировать RecipientInfo
			final RecipientInfo recipientInfo = new RecipientInfo();
			envelopedData.recipientInfos.elements[z] = recipientInfo;
			/*
			 *  RecipientInfo ::= CHOICE {
             * 		ktri KeyTransRecipientInfo, -> KeyTransRecipientInfo ::= SEQUENCE {
             * 											version CMSVersion,  -- always set to 0 or 2
             * 											rid RecipientIdentifier,
             * 											keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
             * 											encryptedKey EncryptedKey }
             * 		kari [1] KeyAgreeRecipientInfo, -> не наш вариант
             * 		kekri [2] KEKRecipientInfo, 	-> не наш вариант
             * 		pwri [3] PasswordRecipientinfo, -> не наш вариант
             * 		ori [4] OtherRecipientInfo }	-> не наш вариант
			 */
			
			final KeyTransRecipientInfo keytrans = new KeyTransRecipientInfo();
			
			// KeyTransRecipientInfo:version
			keytrans.version = new CMSVersion(0);
			
			final Asn1BerEncodeBuffer ebuf = new Asn1BerEncodeBuffer();
			final SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo();
			final Asn1BerDecodeBuffer dbuff = new Asn1BerDecodeBuffer(randomSigner.getCert().getPublicKey().getEncoded());
			spki.decode(dbuff);
			dbuff.reset();
			
			// KeyTransRecipientInfo:keyEncryptionAlgorithm
			final AlgIdInterface algid = new AlgIdSpec(spki.algorithm);
			final AlgorithmIdentifier id = (AlgorithmIdentifier) algid.getDecoded();
			id.encode(ebuf);
			Asn1BerDecodeBuffer dbuf = new Asn1BerDecodeBuffer(ebuf.getMsgCopy());
			keytrans.keyEncryptionAlgorithm = new KeyEncryptionAlgorithmIdentifier();
			keytrans.keyEncryptionAlgorithm.decode(dbuf);
			ebuf.reset();
			dbuf.reset();
			
			// KeyTransRecipientInfo:rid
			keytrans.rid = new RecipientIdentifier();
			final IssuerAndSerialNumber issuer = new IssuerAndSerialNumber();
			final X500Principal issuerName = recipient.getCert().getIssuerX500Principal();
			dbuf = new Asn1BerDecodeBuffer(issuerName.getEncoded());
			issuer.issuer = new Name();
			final RDNSequence rnd = new RDNSequence();
			rnd.decode(dbuf);
			issuer.issuer.set_rdnSequence(rnd);
			issuer.serialNumber = new CertificateSerialNumber(recipient.getCert().getSerialNumber());
			keytrans.rid.set_issuerAndSerialNumber(issuer);
			dbuf.reset();
			
			// KeyTransRecipientInfo:encryptedKey
			final GostR3410_KeyTransport encrKey = new GostR3410_KeyTransport();
			dbuf = new Asn1BerDecodeBuffer(key);
			encrKey.sessionEncryptedKey = new Gost28147_89_EncryptedKey();
			encrKey.sessionEncryptedKey.decode(dbuf);
			dbuf.reset();
			encrKey.transportParameters = new GostR3410_TransportParameters();
			encrKey.transportParameters.encryptionParamSet = new Gost28147_89_ParamSet(algid.getCryptParams().getOID().value);
			encrKey.transportParameters.ephemeralPublicKey = new SubjectPublicKeyInfo();
			dbuf = new Asn1BerDecodeBuffer(randomSigner.getCert().getPublicKey().getEncoded());
			encrKey.transportParameters.ephemeralPublicKey.decode(dbuf);
			dbuf.reset();
			encrKey.transportParameters.ukm = new Asn1OctetString(sv);
			encrKey.encode(ebuf);
			keytrans.encryptedKey = new EncryptedKey(ebuf.getMsgCopy());
			ebuf.reset();
			
			// Устанавливаем получивнийся KeyTransRecipientInfo в RecipientInfo
			recipientInfo.set_ktri(keytrans);
			
		}
		
		// EnvelopedData:encryptedContentInfo
		envelopedData.encryptedContentInfo = new EncryptedContentInfo();
		final OID contentType = new OID("1.2.840.113549.1.7.1");
		envelopedData.encryptedContentInfo.contentType = new ContentType(contentType.value);
		final Gost28147_89_Parameters params = new Gost28147_89_Parameters();
		params.iv = new Gost28147_89_IV(initializationVector);
		params.encryptionParamSet = new Gost28147_89_ParamSet(paramss.getOID().value);
		envelopedData.encryptedContentInfo.contentEncryptionAlgorithm = new ContentEncryptionAlgorithmIdentifier(_Gost28147_89_EncryptionSyntaxValues.id_Gost28147_89, params);
		envelopedData.encryptedContentInfo.encryptedContent = new EncryptedContent(enctryptedData);
		
		// Помещаем во внешнюю оболочку
		final ContentInfo contentInfo = new ContentInfo();
		contentInfo.contentType = new Asn1ObjectIdentifier(new OID(ENVELOPED_DATA_OID).value);
		contentInfo.content = envelopedData;
		
		final Asn1BerEncodeBuffer contentInfoEncodeBuffer = new Asn1BerEncodeBuffer();
		contentInfo.encode(contentInfoEncodeBuffer);
		
		return contentInfoEncodeBuffer.getMsgCopy();
	}
	
	@SuppressWarnings("restriction")
	public ContentInfo _signAttached(byte[] data) throws Exception {
		/*
		 *  SignedData ::= SEQUENCE {
		 * 		version CMSVersion,
		 * 		digestAlgorithms DigestAlgorithmIdentifiers,
		 * 		encapContentInfo EncapsulatedContentInfo,
		 * 		certificates [0] IMPLICIT CertificateSet OPTIONAL,
		 * 		crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
		 * 		signerInfos SignerInfos 
		 * 	}
		 */
		final int signerListSize = signers.size();
		final ContentInfo contentSign = new ContentInfo();
		contentSign.contentType = new Asn1ObjectIdentifier(new OID(SIGNED_DATA_OID).value);
		final SignedData signedData = new SignedData();
		contentSign.content = signedData;
		
		// version
		signedData.version = new CMSVersion(1);
		
		// digestAlgorithms
		signedData.digestAlgorithms = new DigestAlgorithmIdentifiers(signerListSize);
		for (int z = 0; z < signerListSize; z++) {
			final DigestAlgorithmIdentifier a = new DigestAlgorithmIdentifier(new OID(JCP.GOST_DIGEST_OID).value);
			a.parameters = new Asn1Null();
			signedData.digestAlgorithms.elements[z] = a;
		}
		
		// encapContentInfo
		signedData.encapContentInfo = createEncapsulatedContentInfo(data);
		
		// certificates -> CertificateSet ::= SET OF CertificateChoices
		signedData.certificates = new CertificateSet(1);
		signedData.certificates.elements = new CertificateChoices[signerListSize];
		for (int z = 0; z < signerListSize; z++) {
			Signer sig = signers.get(z);
			
			final Certificate certificate = new Certificate(); // ASN.1
			final Asn1BerDecodeBuffer decodeBuffer = new Asn1BerDecodeBuffer(sig.getCert().getEncoded());
			certificate.decode(decodeBuffer);
			
			signedData.certificates.elements[z] = new CertificateChoices();
			signedData.certificates.elements[z].set_certificate(certificate);
		}
		
		// signerInfos -> SignerInfos ::= SET OF SignerInfo
		signedData.signerInfos = new SignerInfos(signerListSize);
		for (int z = 0; z < signerListSize; z++) {
			Signer sig = signers.get(z);
			
			final Signature signature = Signature.getInstance(JCP.GOST_EL_SIGN_NAME);
			signature.initSign(sig.getKey());
			signature.update(data);
			final byte[] sign = signature.sign();
			
			signedData.signerInfos.elements[z] = new SignerInfo();
			signedData.signerInfos.elements[z].version = new CMSVersion(1);
			signedData.signerInfos.elements[z].sid = new SignerIdentifier();
			
			final byte[] encodedName = sig.getCert().getIssuerX500Principal().getEncoded();
			final Asn1BerDecodeBuffer nameBuf = new Asn1BerDecodeBuffer(encodedName);
			final Name name = new Name();
			name.decode(nameBuf);
			
			final CertificateSerialNumber num = new CertificateSerialNumber(sig.getCert().getSerialNumber());
			signedData.signerInfos.elements[z].sid.set_issuerAndSerialNumber(new IssuerAndSerialNumber(name, num));
			signedData.signerInfos.elements[z].digestAlgorithm = new DigestAlgorithmIdentifier(new OID(JCP.GOST_DIGEST_OID).value);
			signedData.signerInfos.elements[z].digestAlgorithm.parameters = new Asn1Null();
			signedData.signerInfos.elements[z].signatureAlgorithm = new SignatureAlgorithmIdentifier(new OID(JCP.GOST_EL_KEY_OID).value);
			signedData.signerInfos.elements[z].signatureAlgorithm.parameters = new Asn1Null();
			signedData.signerInfos.elements[z].signature = new SignatureValue(sign);
		}
		
		return contentSign;
	}

	public byte[] signAttached(byte[] data) throws Exception {
		final ContentInfo contentSign = _signAttached(data);
		
		// encoding
		final Asn1BerEncodeBuffer asnBuf = new Asn1BerEncodeBuffer();
		contentSign.encode(asnBuf, true);
		
		// данные для envelopedData
		final byte[] bufferContentInfo = asnBuf.getMsgCopy();
		return bufferContentInfo;
	}

	private EncapsulatedContentInfo createEncapsulatedContentInfo(byte[] data) {
		return new EncapsulatedContentInfo(new Asn1ObjectIdentifier(new OID(ENCAP_CONTENT_INDO_OID).value), new Asn1OctetString(data));
	}

	/**
	 * Генерация нового симметричного ключа GOST28147.
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 */
	private SecretKey generateRandomSimmetricKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		final KeyGenerator kg = KeyGenerator.getInstance(GOST28147_ALG);
		kg.init(paramss);
		final SecretKey simmetricKey = kg.generateKey();
		return simmetricKey;
	}
	
	/**
	 * Генерация ключа согласования по DH
	 * @param senderKey - PrivateKey отправителя
	 * @param responderPublic - PublicKey получателя
	 * @return сгенерированный SecretKey по GOST28147
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 */
	private SecretKey generateDHAgreementKey(PrivateKey senderKey, PublicKey responderPublic) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
		final KeyAgreement senderKeyAgree = KeyAgreement.getInstance(JCP.GOST_DH_NAME);
		senderKeyAgree.init(senderKey, new IvParameterSpec(sv), null);
		senderKeyAgree.doPhase(responderPublic, true);
		final SecretKey secret = senderKeyAgree.generateSecret("GOST28147");
		return secret;
	}
	
	public byte[] decrypt(byte[] ciphertext) throws Exception {
		//разбор CMS-сообщения
	    Asn1BerDecodeBuffer dbuf = new Asn1BerDecodeBuffer(ciphertext);
	    final ContentInfo all = new ContentInfo();
	    all.decode(dbuf);
	    dbuf.reset();
	    final EnvelopedData cms = (EnvelopedData) all.content;
	    
	    RecipientInfo[] recipientInfos = cms.recipientInfos.elements;
	    
	    // Вращаем получателей
	    for (RecipientInfo recipientInfo : recipientInfos) {
	    	
	    	KeyTransRecipientInfo keytrans = new KeyTransRecipientInfo();
		    
	    	if (recipientInfo.getChoiceID() == RecipientInfo._KTRI) {
		        keytrans = (KeyTransRecipientInfo) recipientInfo.getElement();
		    } else {
		    	LOG.warning("RecipientInfo type unsupported. KeyTransRecipientInfo (ktri) supported only. RecipientInfo type is " + recipientInfo.getElemName());
		    	continue;
		    }
		    
		    // Идентификация получателя
		    String recipientAliase = lookupKeyAlias(keytrans.rid);
		    if (recipientAliase == null) {
		    	LOG.warning("Skip RecipientInfo because RI in a keystore not found by SERIAL or SKI or unknown type -> " + keytrans.rid.getElemName());
		    	continue;
		    }
		    
		    PrivateKey recipientPrivateKey = getKeyFromStore(recipientAliase, storePassword);
		    
		    // разбор параметров ключа
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
		    
		    // зашифрованная нагрузка
		    final byte[] encryptedData = cms.encryptedContentInfo.encryptedContent.value;
		    
		    //отправитель - открытый ключ из cms
		    final X509EncodedKeySpec pspec = new X509EncodedKeySpec(encodedPub);
		    final KeyFactory kf = KeyFactory.getInstance(JCP.GOST_DH_NAME);
		    final PublicKey senderPublicKey = kf.generatePublic(pspec);
		    
		    // выработка ключа согласования получателем
		    final KeyAgreement responderKeyAgree = KeyAgreement.getInstance(JCP.GOST_DH_NAME);
		    responderKeyAgree.init(recipientPrivateKey, new IvParameterSpec(sv), null);
		    responderKeyAgree.doPhase(senderPublicKey, true);
		    final SecretKey agreemtntKey = responderKeyAgree.generateSecret("GOST28147");

		    // Расшифрование симметричного ключа.
		    final Cipher cipher = Cipher.getInstance(CIPHER_MODE);
		    cipher.init(Cipher.UNWRAP_MODE, agreemtntKey, (SecureRandom) null);
		    final SecretKey simmKey = (SecretKey) cipher.unwrap(wrapKey, null, Cipher.SECRET_KEY);
		    
		    // Расшифрование текста на симметричном ключе.
		    final GostCipherSpec spec = new GostCipherSpec(iv, cipherOID);
		    cipher.init(Cipher.DECRYPT_MODE, simmKey, spec, null); 
		    byte[] result = cipher.doFinal(encryptedData, 0, encryptedData.length);
		    return result;
	    }
		throw new GeneralSecurityException("Decription failed. No one suitable recipient.");
	}
	
	/**
	 * Поиск алиаса ключа (и сертификата) в хранилище по RecipientIdentifier.
	 * Поиск производится по SERIAL или SKI в сертификатах + наличие по тому же алиасу ключа.
	 * @param recipientIdentifier RecipientIdentifier
	 * @return Алиас соответствующий сертификату по данным из RI. (Serial или SubjectKeyIdentefer(cert extension)). Или null если соответствующий сертификат не найден.
	 * @throws RecipientIdentifierNotFound
	 * @throws KeyStoreException 
	 */
	private String lookupKeyAlias(RecipientIdentifier recipientIdentifier) throws KeyStoreException {
		String res = null;
		if (recipientIdentifier.getChoiceID() == RecipientIdentifier._ISSUERANDSERIALNUMBER) {
			IssuerAndSerialNumber issuerAndSerialNumber = (IssuerAndSerialNumber) recipientIdentifier.getElement();
			BigInteger serialNumber = issuerAndSerialNumber.serialNumber.value;
			
			Enumeration<String> aliasesEnum = getKeyStore().aliases();
			while(aliasesEnum.hasMoreElements()) {
				String currentAlias = aliasesEnum.nextElement();
				X509Certificate cer = getCertificateFromStore(currentAlias);
				if (cer.getSerialNumber().equals(serialNumber) && getKeyStore().isKeyEntry(currentAlias)) {
					res = currentAlias;
					break;
				}
			}
			
		} else if (recipientIdentifier.getChoiceID() == RecipientIdentifier._SUBJECTKEYIDENTIFIER) {
			SubjectKeyIdentifier subjectKeyIdentifier = (SubjectKeyIdentifier) recipientIdentifier.getElement();
			byte[] ski = subjectKeyIdentifier.value;
			
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

		} else {
			LOG.warning("Unknown RecipientIdentifier type encounted. Type is " + recipientIdentifier.getElemName());
		}
		
		return res;
	}

	public void verify(byte[] signed) throws Exception {
		// TODO Auto-generated method stub

	}

	public byte[] detach(byte[] signed) throws Exception {
		// TODO Auto-generated method stub
		return null;
	}

}
