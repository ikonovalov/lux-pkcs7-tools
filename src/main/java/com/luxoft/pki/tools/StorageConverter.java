package com.luxoft.pki.tools;

import ru.signalcom.crypto.provider.SignalCOMProvider;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

/**
 * @author Timofey Tishin (timtish@gmail.com)
 * С использованием элементов кода Григория Панова (http://grigory-panov.blogspot.ru/2012/03/signal-com.html)
 */
public class StorageConverter {

	private static final String PROVIDER = "SC";

	public static void main(String... params) {
		if (params.length < 1) {
			printHelp();
			return;
		}

		//Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Security.addProvider(new SignalCOMProvider());

		try {
			if (params.length < 3) {
				File file = new File(params[0]);
				String password = params.length > 1 ? params[1] : "";
				if (file.isDirectory()) {
					showDirectoryKeyStoreInfo(params[0], PROVIDER);
				} else {
					showFileKeyStoreInfo(params[0], password, PROVIDER);
				}
				return;
			}

			if (params.length == 3) {
				String rootPath = params[0];
				String storageFileName = params[1];
				String password = params[2];

				// чтение хранилища
				KeyStore store = loadKeyStore(storageFileName, password, PROVIDER);
				addFilesToKeyStore(store, rootPath, password, PROVIDER);

				// запись хранилища
				FileOutputStream out = new FileOutputStream(new File(storageFileName));
				store.store(out, password.toCharArray());
				out.close();
				System.out.println("Storage saved to file " + storageFileName + " password: " + password);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static void printHelp() {
		System.out.println("Key Storage Converter");
		System.out.println("params for convert to PKCS12: sourceDirectoryPath destinationStoreFileName newPassword");
		System.out.println("params for show storage info: storePath [password]");
	}

	private static KeyStore addFilesToKeyStore(KeyStore store, String rootPath, String passwd, String provider) throws GeneralSecurityException, IOException {

		// Формирование цепочки сертификатов
		List<X509Certificate> certificates = new ArrayList<X509Certificate>();
		Set<X509Certificate> rootCertificates = new HashSet<X509Certificate>();
		Set<X509Certificate> otherCertificates = new HashSet<X509Certificate>();
		List<PrivateKey> privateKeys = new ArrayList<PrivateKey>();

		System.out.println("Key storage list:");
		// Чтение сертификатов и ключей
		Queue<File> dirs = new LinkedList<File>();
		dirs.add(new File(rootPath));
		while (!dirs.isEmpty()) {
			File[] files = dirs.poll().listFiles();
			if (files == null) continue;

			for (File certFile: files) {

				// обход всех вложенных директорий
				if (certFile.isDirectory()) {
					dirs.add(certFile);
					continue;
				}

				// чтение сертификата
				X509Certificate cert = (X509Certificate) readCertificateFromFile(certFile, provider);
				if (cert != null) {
					boolean isRoot = PKIXUtils.isSelfSigned(cert);

					certificates.add(cert);
					System.out.println("cert " + certificates.size() + " " + certFile.getName()
							+ (isRoot ? " (self signed) " : " ")
							+ cert.getSubjectDN().getName()
							+ " SerialNumber:" + cert.getSerialNumber());

					if (isRoot) {
						rootCertificates.add(cert);
					} else {
						otherCertificates.add(cert);
					}

					String alias = certFile.getName();
					if (alias.contains(".")) alias = alias.substring(0, alias.lastIndexOf('.'));

					if (store.containsAlias(alias)) {
						store.deleteEntry(alias);
						System.out.println("REWRITE cert " + alias + " [" + cert.getSubjectDN().getName() + "]");
					} else {
						System.out.println("ADD cert " + alias + " [" + cert.getSubjectDN().getName() + "]");
					}
					store.setCertificateEntry(alias, cert);

				} else {

					PrivateKey priv = readPrivateKeyFromFile(certFile, provider);

					if (priv != null) {
						privateKeys.add(priv);

						System.out.println("private key " + privateKeys.size() + " " + certFile.getName());
					}
				}
			}
		}

		for (int keyIndex = 1; keyIndex <= privateKeys.size(); keyIndex++) {

			if (certificates.isEmpty()) throw new IllegalArgumentException("Not found certificates for private key");
			int selectedIndex;
			do {
				System.out.print("select cert for private key " + keyIndex + " [1.." + certificates.size() + "]: ");
				selectedIndex = System.in.read() - '0';
			} while (selectedIndex < 1 || selectedIndex > certificates.size());

			X509Certificate cert = certificates.get(selectedIndex - 1);
			String alias = store.getCertificateAlias(cert);

			// Помещение в хранилище секретного ключа с цепочкой сертификатов
			PKIXCertPathBuilderResult certPath = CertificateVerifier.buildCertificateChain(cert, rootCertificates, otherCertificates, provider);
			List<X509Certificate> certs = (List<X509Certificate>) certPath.getCertPath().getCertificates();
			X509Certificate[] chainArray = new X509Certificate[certs.size()];
			for (int i = 0; i < certs.size(); i++) chainArray[i] = certs.get(i);

			System.out.println("ADD private key " + alias + " [password: " + passwd + ", chain length: " + chainArray.length + ", " + cert.getSubjectDN().getName() +"]");
			store.setKeyEntry(alias, privateKeys.get(keyIndex - 1), passwd.toCharArray(), chainArray);
		}

		return store;
	}

	private static void showDirectoryKeyStoreInfo(String rootPath, String provider) throws GeneralSecurityException, IOException {
		Queue<File> dirs = new LinkedList<File>();
		dirs.add(new File(rootPath));
		while (!dirs.isEmpty()) {
			File[] files = dirs.poll().listFiles();
			if (files == null) continue;

			for (File certFile: files) {

				// обход всех вложенных директорий
				if (certFile.isDirectory()) {
					dirs.add(certFile);
					continue;
				}

				// чтение сертификата
				Certificate cert = readCertificateFromFile(certFile, provider);
				if (cert != null) {
					if (PKIXUtils.isX509Certificate(cert)) {
						System.out.println("cert " + certFile.getName()
								+ (PKIXUtils.isSelfSigned((X509Certificate) cert) ? " (self signed) [" : " [")
								+ ((X509Certificate) cert).getSubjectDN().getName()
								+ "] SerialNumber:" + ((X509Certificate) cert).getSerialNumber()
								+ " " + ((X509Certificate) cert).getSigAlgName());
					} else {
						System.out.println("cert " + certFile.getName() + " " + cert.getType());
					}
				} else {
					// чтение ключа
					PrivateKey priv = readPrivateKeyFromFile(certFile, provider);
					if (priv != null) {
						System.out.println("private key " + certFile.getName() + " " + priv.getFormat() + " " + priv.getAlgorithm());
					}
				}
			}
		}
	}

	private static void showFileKeyStoreInfo(String filePath, String password, String provider) throws GeneralSecurityException, IOException {
		KeyStore store = loadKeyStore(filePath, password, provider);
		if (store == null) return;

		Enumeration<String> aliases = store.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();

			if (store.isKeyEntry(alias)) {
				System.out.println("private key " + alias);

				int certIndex = 1;
				Certificate[] certs = store.getCertificateChain(alias);
				for (Certificate cert : certs) {
					if (PKIXUtils.isX509Certificate(cert)) {
						System.out.println("  " + (certIndex++)  + ". cert "
								+ (PKIXUtils.isSelfSigned((X509Certificate) cert) ? " (self signed) [" : " [")
								+ ((X509Certificate) cert).getSubjectDN().getName()
								+ "] SerialNumber:" + ((X509Certificate) cert).getSerialNumber()
								+ " " + ((X509Certificate) cert).getSigAlgName());
					} else {
						System.out.println("cert " + alias + " " + cert.getType());
					}
				}
			} else if (store.isCertificateEntry(alias)) {
				Certificate cert = store.getCertificate(alias);
				if (PKIXUtils.isX509Certificate(cert)) {
					System.out.println("cert " + alias
							+ (PKIXUtils.isSelfSigned((X509Certificate) cert) ? " (self signed) [" : " [")
							+ ((X509Certificate) cert).getSubjectDN().getName()
							+ "] SerialNumber:" + ((X509Certificate) cert).getSerialNumber()
							+ " " + ((X509Certificate) cert).getSigAlgName());
				} else {
					System.out.println("cert " + alias + " " + cert.getType());
				}
			}
		}
	}

	private static KeyStore loadKeyStore(String filePath, String password, String provider) throws GeneralSecurityException, IOException {
		KeyStore store = KeyStore.getInstance("PKCS#12", provider);

		File file = new File(filePath);
		if (!file.exists()) {
			store.load(null, null);
			return store;
		}

		FileInputStream in = new FileInputStream(file);
		try {
			store.load(in, password.toCharArray());
			return store;
		} catch (GeneralSecurityException e) {
			throw new IOException("Can't load key store " + e.getLocalizedMessage());
		} finally {
			in.close();
		}
	}

	private static Certificate readCertificateFromFile(File certFile, String provider) throws IOException {
		Certificate cert;
		FileInputStream in = new FileInputStream(certFile);
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509", provider);
			cert = cf.generateCertificate(in);
		} catch (GeneralSecurityException e) {
			return null;
		} finally {
			in.close();
		}
		return cert;
	}

	private static PrivateKey readPrivateKeyFromFile(File certFile, String provider) throws IOException {
		try {
			// Чтение секретного ключа PKCS#8
			KeyFactory keyFac = KeyFactory.getInstance("PKCS#8", provider);
			byte[] encoded = readAsBytes(certFile);
			KeySpec privkeySpec = new PKCS8EncodedKeySpec(encoded);
			PrivateKey priv = keyFac.generatePrivate(privkeySpec);
			return priv;
		} catch (GeneralSecurityException e) {
			return null;
		}
	}

	/**
	 * Чтение текстовых данных из потока.
	 *
	 * @return
	 * @throws IOException
	 */
	private static byte[] readAsBytes(File file) throws IOException {
		List<Byte> result = new ArrayList<Byte>();
		InputStream stream = new FileInputStream(file);
		try {
			byte[] buffer = new byte[1024];
			while (stream.available() > 0) {
				int count = stream.read(buffer);
				for (int index = 0; index < count; index++) {
					result.add(buffer[index]);
				}
			}
		} finally {
			stream.close();
		}
		byte[] res = new byte[result.size()];
		for (int index = 0; index < res.length; index++) {
			res[index] = result.get(index);
		}
		return res;
	}

}
