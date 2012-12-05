package com.luxoft.pki.tools;

import ru.signalcom.crypto.provider.SignalCOMProvider;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

/**
 * @author Timofey Tishin (timtish@gmail.com)
 * С использованием элементов кода Григория Панова (http://grigory-panov.blogspot.ru/2012/03/signal-com.html)
 */
public class StorageConverter {

	public static void main(String... params) {
		if (params.length < 3) {
			printHelp();
			return;
		}

		String rootPath = params[0];
		String storageFileName = params[1];
		String passwd = params[2];

		try {
			//Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			Security.addProvider(new SignalCOMProvider());

			// чтение хранилища
			KeyStore store = readKeyStoreFromFiles(rootPath, passwd, "SC");

			// Запись хранилища
			FileOutputStream out = new FileOutputStream(new File(storageFileName));
			store.store(out, passwd.toCharArray());
			out.close();
			System.out.println("Storage saved to file " + storageFileName + " password: " + passwd);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private static void printHelp() {
		System.out.println("Key Storage Converter");
		System.out.println("params: sourceDirectoryPath storageFileName password");
	}

	private static KeyStore readKeyStoreFromFiles(String rootPath, String passwd, String provider) throws GeneralSecurityException, IOException {

		// Инициализация хранилища
		KeyStore store = KeyStore.getInstance("PKCS#12", provider);
		store.load(null, null);

		// Формирование цепочки сертификатов
		List<X509Certificate> certificates = new ArrayList<X509Certificate>();
		Set<X509Certificate> rootCertificates = new HashSet<X509Certificate>();
		Set<X509Certificate> otherCertificates = new HashSet<X509Certificate>();
		Map<PrivateKey, String> privateKeys = new HashMap<PrivateKey, String>();

		// Чтение сертификатов и ключей
		CertificateFactory cf = CertificateFactory.getInstance("X.509", provider);
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
				X509Certificate cert;
				FileInputStream in = new FileInputStream(certFile);
				try {
					cert = (X509Certificate) cf.generateCertificate(in);
					boolean isRoot = PKIXUtils.isSelfSigned(cert);

					certificates.add(cert);
					System.out.println("cert " + certificates.size() + (isRoot ? " (self signed) " : " ") + cert.getSubjectDN().getName() + " SerialNumber:" + cert.getSerialNumber());

					if (isRoot) {
						rootCertificates.add(cert);

						// добавление самоподписанных в trusted
						String certAlias = "CA" + rootCertificates.size();
						store.setCertificateEntry(certAlias, cert);
						System.out.println("add trusted cert " + certAlias + " [" + cert.getSubjectDN().getName() + "]");
					} else {
						otherCertificates.add(cert);
					}
					continue;
				} catch (Exception e) {
					//System.out.println("Can't read certificate from " + certFile.getName() + " Error: " + e.getLocalizedMessage());
				} finally {
					in.close();
				}

				try {
					// Чтение секретного ключа PKCS#8
					KeyFactory keyFac = KeyFactory.getInstance("PKCS#8", provider);
					byte[] encoded = readAsBytes(certFile);
					KeySpec privkeySpec = new PKCS8EncodedKeySpec(encoded);
					PrivateKey priv = keyFac.generatePrivate(privkeySpec);
					privateKeys.put(priv, certFile.getName());
				} catch (Exception e) {
					//System.out.println("Can't read key from " + certFile.getName() + " Error: " + e.getLocalizedMessage());
				}
			}
		}

		if (privateKeys.isEmpty()) {
			System.out.println("Not found private keys");
		}

		int keyIndex = 1;
		for (PrivateKey priv : privateKeys.keySet()) {
			if (certificates.isEmpty()) throw new IllegalArgumentException("Not found certificates for private key");
			int selectedIndex;
			do {
				System.out.print("select cert for private key " + privateKeys.get(priv) + " [1.." + certificates.size() + "]: ");
				selectedIndex = System.in.read() - '0';
			} while (selectedIndex < 1 || selectedIndex > certificates.size());

			String alias = "KEY" + (keyIndex++);
			X509Certificate cert = certificates.get(selectedIndex - 1);

			// Помещение в хранилище секретного ключа с цепочкой сертификатов
			PKIXCertPathBuilderResult certPath = CertificateVerifier.buildCertificateChain(cert, rootCertificates, otherCertificates, provider);
			List<X509Certificate> certs = (List<X509Certificate>) certPath.getCertPath().getCertificates();
			X509Certificate[] chainArray = new X509Certificate[certs.size()];
			for (int i = 0; i < certs.size(); i++) chainArray[i] = certs.get(i);

			System.out.println("add key " + alias + " [password: " + passwd + ", chain length: " + chainArray.length + ", " + cert.getSubjectDN().getName() +"]");
			store.setKeyEntry(alias, priv, passwd.toCharArray(), chainArray);
		}

		return store;
	}

	/**
	 * Чтение текстовых данных из потока.
	 *
	 * @return
	 * @throws IOException
	 */
	public static byte[] readAsBytes(File file) throws IOException {
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
