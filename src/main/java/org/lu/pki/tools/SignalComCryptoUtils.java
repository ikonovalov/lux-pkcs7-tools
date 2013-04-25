package org.lu.pki.tools;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import ru.signalcom.crypto.cms.Attribute;
import ru.signalcom.crypto.cms.AttributeType;
import ru.signalcom.crypto.cms.CMSException;
import ru.signalcom.crypto.cms.CipherAlgorithm;
import ru.signalcom.crypto.cms.ContentInfoParser;
import ru.signalcom.crypto.cms.ContentType;
import ru.signalcom.crypto.cms.CounterSignature;
import ru.signalcom.crypto.cms.EnvelopedDataGenerator;
import ru.signalcom.crypto.cms.EnvelopedDataParser;
import ru.signalcom.crypto.cms.Recipient;
import ru.signalcom.crypto.cms.RecipientInfo;
import ru.signalcom.crypto.cms.SignedDataGenerator;
import ru.signalcom.crypto.cms.SignedDataParser;
import ru.signalcom.crypto.cms.Signer;
import ru.signalcom.crypto.cms.SignerInfo;

/**
 * Класс по мотивам примера официальной поставки.
 * Адаптирован: Igor Konovalov - Luxoft (C) - 2012.
 * Примеры использования классов, реализующих протокол CMS (RFC 5652). (От себя: да ладно уж, знаем мы ваше RFC...)
 * Copyright (C) 2010 ЗАО "Сигнал-КОМ".
 */
public final class SignalComCryptoUtils extends CryptoUtils {
    
    private static String STORE_TYPE = "PKCS12";
    private static String CRYPTO_PROVIDER = "SC";
    
    private final String psePath;
    private final String storeFile;
    private final char[] storePassword;

    private final List<Signer> signers = new ArrayList<Signer>();
    private final List<Recipient> recipients = new ArrayList<Recipient>();
    
    private SecureRandom random;
    
    private static Logger LOG = Logger.getLogger(SignalComCryptoUtils.class.getName());
    
    private final List<CertStore> allStoredCertificates = new ArrayList<CertStore>();
    
    /**
     * 
     * @param keystoreFile - путь до pfx или p12 файла-хранилища. На уровне файла должны распологаться файлы генератора случайных чисел.
     * @param password - пароль к хранилищу (или null, если пароль не задан).
     * @throws Exception
     */
    public SignalComCryptoUtils(final String keystoreFile, final String password) throws Exception {
    	if (keystoreFile == null){
    		throw new NullPointerException("Path to keystore is null"); 
    	}
    	storeFile = keystoreFile;
    	storePassword = password != null ? password.toCharArray() : null;
    	psePath = (new File(storeFile)).getParent() + ";NonInteractive" + (storePassword != null ? ";Password="+password : "");
    	if (LOG.isLoggable(Level.FINE)) {
    		LOG.fine("PSE_PATH: " + psePath);
    	}
    	init();
	}
    
    public SignalComCryptoUtils(final String keystoreFile) throws Exception {
    	this(keystoreFile, null);
    }
    
    /**
     * Установка списка Signers. (Все что было в списке до этого будет стерто)
     * @param signerAliases алиасы ключей участвующих в подписании сообщения
     * @return this (SignalComCryptoUtils)
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     */
    public SignalComCryptoUtils signer(String... signerAliases) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
    	signers.clear();
    	if (signerAliases == null) { // ничего не делаем просто очищаем список
    		return this;
    	}
    	for (String signer : signerAliases) {
    		if (getKeyStore().isKeyEntry(signer)) {
    			addSignerToList(signer);
    			LOG.fine("Adding signer with alias " + signer);
    		} else {
    			LOG.warning("Alias " + signer + " doesn't have private key and can't be a signer");
    		}
    	}
    	return this;
    }
    
    /**
     * Установка списка получателей.
     * @param recipientsAliases - список алиасов сертификатов получателей (keyEncipherment or keyAgreement bit required)
     * @return this (SignalComCryptoUtils)
     * @throws KeyStoreException
     */
    public SignalComCryptoUtils recipients(String... recipientsAliases) throws KeyStoreException {
    	recipients.clear();
    	if (recipientsAliases != null) {	
	    	for (String recipient : recipientsAliases) {
	    		addRecipientToList(recipient);
	    	}
    	}
    	return this;
    }

	
    /**
     * Инициализация: чтение ключей, сертификатов и т.д.
     * @throws Exception
     */
    private void init() throws Exception {
    	LOG.fine("RNG initialization...");
        random = SecureRandom.getInstance("GOST28147PRNG", "SC");
        random.setSeed(psePath.getBytes());
        
        KeyStore keyStore = null;

        LOG.fine("Key store loading...");
        keyStore = KeyStore.getInstance(STORE_TYPE, CRYPTO_PROVIDER);
        InputStream in = new FileInputStream(new File(storeFile));
        keyStore.load(in, storePassword);
        in.close();
        setKeyStore(keyStore);
        
        LOG.fine("Load all certificates from store...");
        allStoredCertificates.add(getAllCertificateFromStore());

        CryptoUtils.setCertPathBuilder(CertPathBuilder.getInstance("PKIX", "SC"));
    }

    /**
     * Добавление Signer-а в список подписчиков.
     * @param alias
     * @return Signer's X509Certificate 
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
	private X509Certificate addSignerToList(String alias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
		PrivateKey priv = (PrivateKey) getKeyStore().getKey(alias, storePassword);
		X509Certificate cert = getCertificateFromStore(alias);
		signers.add(new Signer(priv, cert, random));
		return cert;
	}
	
	private X509Certificate addRecipientToList(String recipient) throws KeyStoreException {
		X509Certificate cert = getCertificateFromStore(recipient);
		recipients.add(new Recipient(cert));
		return cert;
	}

    /**
     * Пример формирования подписанного (SignedData) сообщения.
     * @param data подписываемые данные.
     * @param type идентификатор типа подписываемых данных.
     * @param detached если true, то формируется отсоединённая подпись.
     * @return подписанное сообщение.
     * @throws Exception
     */
    private byte[] sign(byte[] data, String type, boolean detached) throws Exception {
        LOG.fine("Signing...");
        InputStream in = new ByteArrayInputStream(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        SignedDataGenerator generator = new SignedDataGenerator(out);
        generator.setContentType(type);
        generator.addSigners(signers);
        generator.setDetached(detached);

        OutputStream sigOut = generator.open();

        byte[] buf = new byte[1024];
        int len;
        while ((len = in.read(buf)) > 0) {
            sigOut.write(buf, 0, len);
        }
        generator.close();
        in.close();
        return out.toByteArray();
    }

    public byte[] signAttached(byte[] data) throws Exception {
        return sign(data, ContentType.DATA, false);
    }

   

    /**
     * Пример проверки блока подписи (SignerInfo).
     * Включает:
     * <br>1) проверку подписи для данных;</br>
     * <br>2) проверку сертификата;</br>
     * <br>3) проверку удостоверяющих подписей (если есть).</br>
     * @param signerInfo блок подписи.
     * @param trust список доверенных сертификатов.
     * @param stores хранилища сертификатов и списков отозванных сертификатов.
     * @throws Exception
     */
    private void verifySignerInfo(SignerInfo signerInfo) throws Exception {
    	
        X509Certificate signerCert = null;
        
        // поиск сертификата в хранилище
        if (signerInfo.getSubjectKeyIdentifier() == null) {
        	signerCert = lookupCertificateBySerialNumber(allStoredCertificates, signerInfo.getIssuer(), signerInfo.getSerialNumber());
        } else {
        	signerCert = lookupCertificateBySubjectKeyIdentefer(allStoredCertificates, signerInfo.getSubjectKeyIdentifier());
        }
        
        if (LOG.isLoggable(Level.FINE)) {
        	LOG.fine("Signature " + signerCert.getSubjectDN().getName() + " verifying...");
        }
        
        // пропскаем самоподписанные сертификаты, если это необходимо.
        if (isFlagSet(OPT_SKIP_SELFSIGNED_CERT) && PKIXUtils.isSelfSigned(signerCert)) {
        	LOG.fine("Skipping self-signed certificate " + signerCert.getSubjectDN().getName());
        	return;
        }
        
        //проверка подписи
        if (!signerInfo.verify(signerCert)) {
            throw new CMSException("Signature " + signerCert.getSubjectDN().getName() +" failure");
        }

        if (isFlagNotSet(OPT_DISABLE_CERT_VALIDATION)) {
        	//verifyCertificate(cert, trust, stores); // это огигинальный вариант проверки из примера
        	CertificateVerifier.verifyCertificate(signerCert, getKeyStore(), isFlagSet(OPT_ALLOW_SELFSIGNED_CERT), "SC"); // а это наш, адаптированный под разные VM
        }
        
        @SuppressWarnings("unchecked")
        Collection<Attribute> attrs = signerInfo.getUnsignedAttributes();
        if (!attrs.isEmpty()) {
            Iterator<Attribute> it2 = attrs.iterator();
            while (it2.hasNext()) {
                Attribute at = it2.next();

                if (at.getType().equals(AttributeType.COUNTER_SIGNATURE)) {
                	LOG.fine("Countersignature was found...");
                    CounterSignature counterSignature = new CounterSignature(at.getValue(), signerInfo);
                    verifySignerInfo(counterSignature);
                }
            }
        }
    }

    /**
     * Пример проверки подписанного (SignedData) сообщения.
     * @param signed подписанное сообщение.
     * @param data данные, используемые при проверке отсоединённой подписи.
     * @throws Exception
     */
    private void verify(byte[] signed, byte[] data) throws Exception {

    	LOG.fine("Signature(s) verifying...");
        InputStream in = new ByteArrayInputStream(signed);
        ContentInfoParser cinfoParser = ContentInfoParser.getInstance(in);
        if (!(cinfoParser instanceof SignedDataParser)) {
            throw new RuntimeException("SignedData expected here");
        }
        SignedDataParser parser = (SignedDataParser) cinfoParser;
        InputStream content = parser.getContent();
        if (content == null) {
            // отсоединённая подпись
            if (data == null) {
                throw new RuntimeException("detached signed data required");
            }
            parser.setContent(new ByteArrayInputStream(data));
        }
        parser.process();
        in.close();
        
        CertStore cmsCertificates = parser.getCertificatesAndCRLs();
        if (isFlagNotSet(OPT_STORED_CERT_ONLY)) { // если это разрешается, то проверка будет производится И на сертификатах пришедших в CMS
        	allStoredCertificates.add(cmsCertificates);
        	if (LOG.isLoggable(Level.FINE)) {
        		LOG.fine("Added " + cmsCertificates.getCertificates(null).size() + " certificate from incoming CMS. Flag OPT_STORED_CERT_ONLY not set.");
        	}
        }

        @SuppressWarnings("unchecked")
        Collection<SignerInfo> signerInfos = parser.getSignerInfos();
        if (LOG.isLoggable(Level.FINE)) {
        	LOG.fine("Total SignerInfo collection size is " + (signerInfos != null ? signerInfos.size() : 0));
        }
        Iterator<SignerInfo> it = signerInfos.iterator();
        while (it.hasNext()) {
            SignerInfo signerInfo = it.next();
            verifySignerInfo(signerInfo);
        }
        parser.close();
    }

    public void verify(byte[] signed) throws Exception {
    	signed = forceBASE64(signed);
        verify(signed, null);
    }

    /**
     * Пример отделения подписанных данных от подписей.
     * @param signed подписанное сообщение.
     * @return подписанные данные.
     * @throws Exception
     */
    public byte[] detach(byte[] signed) throws Exception {
    	signed = forceBASE64(signed);
    	LOG.fine("Data detaching...");
        SignedDataParser parser = new SignedDataParser(new ByteArrayInputStream(signed));
        InputStream content = parser.getContent(false);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        byte[] data = new byte[1024];
        int len;
        while ((len = content.read(data)) >= 0) {
            bOut.write(data, 0, len);
        }
        parser.close();
        return bOut.toByteArray();
    }

    /**
     * Пример формирования зашифрованного (EnvelopedData) сообщения.
     * @param plain открытые данные.
     * @return зашифрованное сообщение.
     * @throws Exception
     */
    public byte[] encrypt(byte[] plain) throws Exception {

    	LOG.fine("Enciphering...");
        InputStream bIn = new ByteArrayInputStream(plain);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        EnvelopedDataGenerator generator = new EnvelopedDataGenerator(bOut, random);
        
        generator.setContentEncryptionAlgorithm(CipherAlgorithm.GOST28147); // устаревший алгоритм. Но что поделать.
        generator.addRecipients(recipients);
        OutputStream out = generator.open();

        byte[] data = new byte[1024];
        int len;
        while ((len = bIn.read(data)) >= 0) {
            out.write(data, 0, len);
        }

        generator.close();
        bIn.close();
        return bOut.toByteArray();
    }

    /**
     * Пример расшифрования EnvelopedData сообщения.
     * @param ciphertext зашифрованное сообщение.
     * @return расшифрованные данные.
     * @throws Exception
     */
    public byte[] decrypt(byte[] ciphertext) throws Exception {
    	ciphertext = forceBASE64(ciphertext);
    	
    	LOG.fine("Deciphering...");
        InputStream bIn = new ByteArrayInputStream(ciphertext);

        ContentInfoParser cinfoParser = ContentInfoParser.getInstance(bIn);
        if (cinfoParser == null) {
        	throw new RuntimeException("Container type undeterminated. Type is " + ContentInfoParser.getContentType(bIn));
        }
        if (!(cinfoParser instanceof EnvelopedDataParser)) {
            throw new RuntimeException("EnvelopedData expected here");
        }
        EnvelopedDataParser parser = (EnvelopedDataParser) cinfoParser;
        @SuppressWarnings("unchecked")
		Collection<RecipientInfo> recInfos = parser.getRecipientInfos();
        Iterator<RecipientInfo> it = recInfos.iterator();
        KeyStore keyStore = getKeyStore();
        while (it.hasNext()) {
            RecipientInfo recInfo = (RecipientInfo) it.next();
            X509Certificate cert = null;
            LOG.fine("Try decrypt for RecipientInfo serial=" + recInfo.getSerialNumber()+ " RI: " + recInfo.getRecipientIdentifier().toString());
            if (recInfo.getSubjectKeyIdentifier() == null) {
            	cert = lookupCertificateBySerialNumber(allStoredCertificates, recInfo.getIssuer(), recInfo.getSerialNumber());
            } else {
            	cert = lookupCertificateBySubjectKeyIdentefer(allStoredCertificates, recInfo.getSubjectKeyIdentifier());
            }
    
            if (cert != null) {
                PrivateKey priv = (PrivateKey) keyStore.getKey(keyStore.getCertificateAlias(cert), storePassword);
                if (priv != null) {
                    InputStream content = recInfo.getEncryptedContent(priv, random);
                    ByteArrayOutputStream bOut = new ByteArrayOutputStream();

                    byte[] data = new byte[1024];
                    int len;
                    while ((len = content.read(data)) >= 0) {
                        bOut.write(data, 0, len);
                    }

                    parser.close();
                    bIn.close();
                    return bOut.toByteArray();
                }
            }
        }
        throw new RuntimeException("recipient's private key not found");
    }
    
    /* private byte[] sign(byte[] data, boolean detached) throws Exception {
    return sign(data, ContentType.DATA, detached);
	}*/
	
	/**
	 * Пример формирования удостоверяющей подписи (countersignature)
	 * для всех подписей, содержащихся в подписанном (SignedData) сообщении.
	 * @param signed подписанное сообщение.
	 * @return новое подписанное сообщение.
	 * @throws Exception
	 */
	/*private byte[] countersign(byte[] signed) throws Exception {
	
	    System.out.println("Countersigning...");
	    InputStream in = new ByteArrayInputStream(signed);
	    ContentInfoParser cinfoParser = ContentInfoParser.getInstance(in);
	    if (!(cinfoParser instanceof SignedDataParser)) {
	        throw new RuntimeException("SignedData expected here");
	    }
	    SignedDataParser parser = (SignedDataParser) cinfoParser;
	    parser.process(false);
	    @SuppressWarnings("unchecked")
	    Collection<SignerInfo> signerInfos = parser.getSignerInfos();
	    Iterator<SignerInfo> it = signerInfos.iterator();
	    while (it.hasNext()) {
	        SignerInfo signerInfo = it.next();
	        Iterator<Signer> it2 = signers.iterator();
	        while (it2.hasNext()) {
	            Signer signer = it2.next();
	            CounterSignatureGenerator gen = new CounterSignatureGenerator(signerInfo);
	            CounterSignature csig = gen.generate(signer);
	            signerInfo.addUnsignedAttribute(
	                    new Attribute(AttributeType.COUNTER_SIGNATURE, csig.getEncoded()));
	        }
	    }
	    parser.close();
	
	    in.reset();
	    ByteArrayOutputStream out = new ByteArrayOutputStream();
	    SignedDataReplacer replacer = new SignedDataReplacer(in, out);
	    replacer.setSignerInfos(signerInfos);
	    replacer.open();
	    replacer.process();
	    replacer.close();
	    in.close();
	    return out.toByteArray();
	}*/
	
	/**
	 * Пример проверки сертификата.
	 * @param cert сертификат.
	 * @param trust список доверенных сертификатов.
	 * @param stores хранилища сертификатов и списков отозванных сертификатов.
	 * @return результат проверки.
	 * @throws Exception
	 */
	/*private PKIXCertPathBuilderResult verifyCertificate(X509Certificate cert, Set<TrustAnchor> trust, List<CertStore> stores) throws Exception {
	
		LOG.fine("X.509 certificate verifying...");
		LOG.fine("Subject: " + cert.getSubjectX500Principal());
		
		System.out.println("Trusted cnt: " + trust.size());
		System.out.println("Stores: " + stores.size());
		
	    X509CertSelector csel = new X509CertSelector();      
	    csel.setCertificate(cert);
	
	    PKIXParameters params = new PKIXBuilderParameters(trust, csel);
	    params.setCertStores(stores);
	    params.setRevocationEnabled(true);
	
	    CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", "SC");
	    PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) cpb.build(params);
	    LOG.fine("Trust anchor: " + result.getTrustAnchor().getTrustedCert().getIssuerX500Principal());
	    return result;
	}*/
}
