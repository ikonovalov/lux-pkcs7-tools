package com.luxoft.pkcs7.cms.tests;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import ru.CryptoPro.JCP.params.AlgIdSpec;
import ru.CryptoPro.JCP.params.OID;
import ru.CryptoPro.JCPRequest.GostCertificateRequest;

public class St1CreateCertAndKeys {

	public static final String CONT_NAME_RAPIDA = "Rapida";

	public static final char[] PASSWORD_RAPIDA = "a".toCharArray();

	public static final String DNAME_RAPIDA = "CN=Container_Rapida, O=Rapida, C=RU";
	
	

	public static final String CONT_NAME_TINKOFF = "Tinkoff";

	public static final char[] PASSWORD_TINKOFF = "b".toCharArray();

	public static final String DNAME_TINKOFF = "CN=Container_Tinkoff, O=Tinkoff, C=RU";

	public static void main(String[] args) throws Exception {

		// генерирование ключевой пары ЭЦП и запись в хранилище
		saveKeyWithCert(genKey(Constants.SIGN_KEY_PAIR_ALG + "DH"), CONT_NAME_RAPIDA, PASSWORD_RAPIDA, DNAME_RAPIDA);

		// генерирование ключевой пары ЭЦП с параметрами и запись в хранилище
		//saveKeyWithCert(genKeyWithParams(Constants.EXCH_KEY_PAIR_ALG), CONT_NAME_TINKOFF, PASSWORD_TINKOFF, DNAME_TINKOFF);
		saveKeyWithCert(genKey(Constants.SIGN_KEY_PAIR_ALG + "DH"), CONT_NAME_TINKOFF, PASSWORD_TINKOFF, DNAME_TINKOFF);

		// загрузка содержимого хранилища для чтения ключа
		final KeyStore hdImageStore = KeyStore.getInstance(Constants.KEYSTORE_TYPE);
		// загрузка содержимого носителя (предполагается, что не существует
		// хранилища доверенных сертификатов)
		hdImageStore.load(null, null);

		// получение закрытого ключа из хранилища
		final PrivateKey keyA = (PrivateKey) hdImageStore.getKey(CONT_NAME_RAPIDA, PASSWORD_RAPIDA);
		final PrivateKey keyB = (PrivateKey) hdImageStore.getKey(CONT_NAME_TINKOFF, PASSWORD_TINKOFF);

		System.out.println("OK");
	}

	/**
	 * генерирование ключевой пары
	 * 
	 * @param algorithm
	 *            алгоритм
	 * @return ключевая пара
	 * @throws Exception
	 *             /
	 */
	public static KeyPair genKey(String algorithm) throws Exception {

		// создание генератора ключевой пары
		final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);

		// генерирование ключевой пары
		return keyGen.generateKeyPair();
	}

	/**
	 * генерирование ключевой пары с параметрами
	 * 
	 * @param algorithm
	 *            алгоритм
	 * @return ключевая пара
	 * @throws Exception
	 *             /
	 */
	public static KeyPair genKeyWithParams(String algorithm) throws Exception {

		final OID keyOid = new OID("1.2.643.2.2.19");
		final OID signOid = new OID("1.2.643.2.2.35.2");
		final OID digestOid = new OID("1.2.643.2.2.30.1");
		final OID cryptOid = new OID("1.2.643.2.2.31.1");

		// создание генератора ключевой пары ЭЦП
		final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);

		// определение параметров генератора ключевой пары
		final AlgIdSpec keyParams = new AlgIdSpec(keyOid, signOid, digestOid, cryptOid);
		keyGen.initialize(keyParams);

		// генерирование ключевой пары
		return keyGen.generateKeyPair();
	}

	/**
	 * Сохранение в хранилище
	 * 
	 * @param pair
	 *            сгенерированная ключевая пара
	 * @param contName
	 *            имя контейнера
	 * @param password
	 *            пароль на контенер
	 * @param dname
	 *            имя субъекта сертификата
	 * @throws Exception
	 *             /
	 */
	public static void saveKeyWithCert(KeyPair pair, String contName, char[] password, String dname) throws Exception {

		// * создание цепочки сертификатов, состоящей из самоподписанного
		// сертификата
		final Certificate[] certs = new Certificate[1];
		certs[0] = genSelfCert(pair, dname);

		// * запись закрытого ключа и цепочки сертификатов в хранилище
		// определение типа ключевого носителя, на который будет осуществлена
		// запись ключа
		final KeyStore hdImageStore = KeyStore.getInstance(Constants.KEYSTORE_TYPE);
		// загрузка содержимого носителя (предполагается, что не существует
		// хранилища доверенных сертификатов)
		hdImageStore.load(null, null);
		// запись на носитель закрытого ключа и цепочки
		hdImageStore.setKeyEntry(contName, pair.getPrivate(), password, certs);
		// сохранение содержимого хранилища
		hdImageStore.store(null, null);
	}

	/**
	 * Генерирование самоподписанного сертификата
	 * 
	 * @param pair
	 *            ключевая пара
	 * @param dname
	 *            имя субъекта сертификата
	 * @return самоподписанный сертификат
	 * @throws Exception
	 *             /
	 */
	public static Certificate genSelfCert(KeyPair pair, String dname) throws Exception {

		// создание генератора самоподписанного сертификата
		final GostCertificateRequest gr = new GostCertificateRequest();
		// генерирование самоподписанного сертификата, возвращаемого в
		// DER-кодировке
		final byte[] enc = gr.getEncodedSelfCert(pair, dname);
		// инициализация генератора X509-сертификатов
		final CertificateFactory cf = CertificateFactory.getInstance(Constants.CF_ALG);
		// генерирование X509-сертификата из закодированного представления
		// сертификата
		return cf.generateCertificate(new ByteArrayInputStream(enc));
	}
}
