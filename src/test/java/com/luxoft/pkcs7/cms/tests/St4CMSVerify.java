/**
 * $RCSfile: CMSVerify.java,v $
 * version $Revision: 1.11 $
 * created 16.08.2007 11:28:24 by kunina
 * last modified $Date: 2009/04/24 11:12:13 $ by $Author: kunina $
 * (C) ООО Крипто-Про 2004-2007.
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

import com.objsys.asn1j.runtime.Asn1BerDecodeBuffer;
import com.objsys.asn1j.runtime.Asn1BerEncodeBuffer;
import com.objsys.asn1j.runtime.Asn1ObjectIdentifier;
import com.objsys.asn1j.runtime.Asn1OctetString;
import com.objsys.asn1j.runtime.Asn1Type;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.ContentInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.DigestAlgorithmIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignedData;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignerInfo;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Attribute;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.params.OID;
import ru.CryptoPro.JCP.tools.Array;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static com.luxoft.pkcs7.cms.tests.CLIParser.*;

/**
 * CMS Verify (поиск сертификатов: 1)CMS, 2)заданные сертификаты, 3)store(?))
 * [Проверка параллельных подписей и подписей с signedAttributes]
 * <p/>
 * Проверяет:
 * <p/>
 * CMS_samples.CMSSign
 * <p/>
 * csptest -lowsign -in data.txt -my key -sign -out data_low.sgn -add
 * <p/>
 * csptest -lowsign -in data.txt -my key -sign -out data_low.sgn (нет вложенного
 * сертификата)
 * <p/>
 * csptest -sfsign -in data.txt -my key -sign -out data_sf.sgn -add
 * <p/>
 * csptest -sfsign -in data.txt -my key -sign -out data_sf.sgn (нет вложенного
 * сертификата)
 * 
 * @author Copyright 2004-2009 Crypto-Pro. All rights reserved.
 * @.Version
 */
public class St4CMSVerify {

	// CMS.java

	private static StringBuffer out = new StringBuffer("");

	private static StringBuffer out1 = new StringBuffer("");

	private static int validsign;

	/**/
	private St4CMSVerify() {

	}

	/**
	 * проверка CMS
	 * 
	 * @param buffer
	 *            буфер
	 * @param certs
	 *            сертификаты
	 * @param data
	 *            данные
	 * @throws Exception
	 *             e
	 */
	public static void cmsVerify(byte[] buffer, Certificate[] certs, byte[] data, String[] args) throws Exception {
		
		CLIParser cli = new CLIParser();
		cli.init(args);
		
		// clear buffers fo logs
		out = new StringBuffer("");
		out1 = new StringBuffer("");
		final Asn1BerDecodeBuffer asnBuf = new Asn1BerDecodeBuffer(buffer);
		final ContentInfo all = new ContentInfo();
		all.decode(asnBuf);
		if (!new OID("1.2.840.113549.1.7.2").eq(all.contentType.value))
			throw new Exception("Not supported");
		final SignedData signedData = (SignedData) all.content;
		final byte[] payloadBytes;
		if (signedData.encapContentInfo.eContent != null)
			payloadBytes = signedData.encapContentInfo.eContent.value;
		else if (data != null)
			payloadBytes = data;
		else
			throw new Exception("No content for verify");
		String dfPath = (cli.contains(DECRYPTED_FILE)? cli.getParam(DECRYPTED_FILE) : null);
		if (dfPath != null) {
			FileOutputStream fos = new FileOutputStream(dfPath);
			fos.write(payloadBytes);
			fos.close();
			System.out.println("Message payload is stored in " + dfPath);
		} else {
			System.out.println("<---------Data start -------->");
			System.out.println(new String(payloadBytes));
			System.out.println("<---------Data end ---------->");
		}
		
		OID digestOid = null;
		final DigestAlgorithmIdentifier digestAlgorithmIdentifier = new DigestAlgorithmIdentifier(new OID(
				JCP.GOST_DIGEST_OID).value);
		for (int i = 0; i < signedData.digestAlgorithms.elements.length; i++) {
			if (signedData.digestAlgorithms.elements[i].algorithm.equals(digestAlgorithmIdentifier.algorithm)) {
				digestOid = new OID(signedData.digestAlgorithms.elements[i].algorithm.value);
				break;
			}
		}
		if (digestOid == null)
			throw new Exception("Unknown digest");
		final OID eContTypeOID = new OID(signedData.encapContentInfo.eContentType.value);
		if (signedData.certificates != null) {
			// Проверка на вложенных сертификатах
			System.out.println("Validation on certificates founded in CMS.");
			for (int i = 0; i < signedData.certificates.elements.length; i++) {
				final Asn1BerEncodeBuffer encBuf = new Asn1BerEncodeBuffer();
				signedData.certificates.elements[i].encode(encBuf);

				final CertificateFactory cf = CertificateFactory.getInstance("X.509");
				final X509Certificate cert = (X509Certificate) cf.generateCertificate(encBuf.getInputStream());

				for (int j = 0; j < signedData.signerInfos.elements.length; j++) {
					final SignerInfo info = signedData.signerInfos.elements[j];
					if (!digestOid.equals(new OID(info.digestAlgorithm.algorithm.value)))
						throw new Exception("Not signed on certificate.");
					final boolean checkResult = verifyOnCert(cert, signedData.signerInfos.elements[j], payloadBytes, eContTypeOID);
					writeLog(checkResult, j, i, cert);
				}
			}
		} else if (certs != null) {
			// Проверка на указанных сертификатах
			System.out.println("Certificates for validation not found in CMS.\n"
					+ "      Try verify on specified certificates...");
			for (int i = 0; i < certs.length; i++) {
				final X509Certificate cert = (X509Certificate) certs[i];
				for (int j = 0; j < signedData.signerInfos.elements.length; j++) {
					final SignerInfo info = signedData.signerInfos.elements[j];
					if (!digestOid.equals(new OID(info.digestAlgorithm.algorithm.value)))
						throw new Exception("Not signed on certificate.");
					final boolean checkResult = verifyOnCert(cert, signedData.signerInfos.elements[j], payloadBytes, eContTypeOID);
					writeLog(checkResult, j, i, cert);
				}
			}
		} else {
			System.out.println("Certificates for validation not found");
		}
		if (validsign == 0)
			throw new Exception("Signatures are invalid" + out1);
		if (signedData.signerInfos.elements.length > validsign)
			throw new Exception("Some signatures are invalid:" + out + out1);
		else
			System.out.println("All signatures are valid:" + out);
	}

	/**
	 * Попытка проверки подписи на указанном сертификате
	 * 
	 * @param cert
	 *            сертификат для проверки
	 * @param text
	 *            текст для проверки
	 * @param info
	 *            подпись
	 * @return верна ли подпись
	 * @throws Exception
	 *             ошибки
	 */
	private static boolean verifyOnCert(X509Certificate cert, SignerInfo info, byte[] text, OID eContentTypeOID)
			throws Exception {

		// подпись
		final byte[] sign = info.signature.value;
		// данные для проверки подписи
		final byte[] data;
		if (info.signedAttrs == null) {
			// аттрибуты подписи не присутствуют
			// данные для проверки подписи
			data = text;
		} else {
			// присутствуют аттрибуты подписи (SignedAttr)
			final Attribute[] signAttrElem = info.signedAttrs.elements;

			// проверка аттрибута content-type
			final Asn1ObjectIdentifier contentTypeOid = new Asn1ObjectIdentifier(
					(new OID("1.2.840.113549.1.9.3")).value);
			Attribute contentTypeAttr = null;

			for (int r = 0; r < signAttrElem.length; r++) {
				final Asn1ObjectIdentifier oid = signAttrElem[r].type;
				if (oid.equals(contentTypeOid)) {
					contentTypeAttr = signAttrElem[r];
				}
			}

			if (contentTypeAttr == null)
				throw new Exception("content-type attribute not present");

			if (!contentTypeAttr.values.elements[0].equals(new Asn1ObjectIdentifier(eContentTypeOID.value)))
				throw new Exception("content-type attribute OID not equal eContentType OID");

			// проверка аттрибута message-digest
			final Asn1ObjectIdentifier messageDigestOid = new Asn1ObjectIdentifier(
					(new OID("1.2.840.113549.1.9.4")).value);

			Attribute messageDigestAttr = null;

			for (int r = 0; r < signAttrElem.length; r++) {
				final Asn1ObjectIdentifier oid = signAttrElem[r].type;
				if (oid.equals(messageDigestOid)) {
					messageDigestAttr = signAttrElem[r];
				}
			}

			if (messageDigestAttr == null)
				throw new Exception("message-digest attribute not present");

			final Asn1Type open = messageDigestAttr.values.elements[0];
			final Asn1OctetString hash = (Asn1OctetString) open;
			final byte[] md = hash.value;

			// вычисление messageDigest
			final byte[] dm = digestm(text, JCP.GOST_DIGEST_NAME);

			if (!Array.toHexString(dm).equals(Array.toHexString(md)))
				throw new Exception("message-digest attribute verify failed");

			// проверка аттрибута signing-time
			final Asn1ObjectIdentifier signTimeOid = new Asn1ObjectIdentifier((new OID("1.2.840.113549.1.9.5")).value);

			Attribute signTimeAttr = null;

			for (int r = 0; r < signAttrElem.length; r++) {
				final Asn1ObjectIdentifier oid = signAttrElem[r].type;
				if (oid.equals(messageDigestOid)) {
					signTimeAttr = signAttrElem[r];
				}
			}

			if (signTimeAttr != null) {
				// проверка (необязательно)
			}

			// данные для проверки подписи
			final Asn1BerEncodeBuffer encBufSignedAttr = new Asn1BerEncodeBuffer();
			info.signedAttrs.encode(encBufSignedAttr);
			data = encBufSignedAttr.getMsgCopy();
		}
		// проверка подписи
		final Signature signature = Signature.getInstance(JCP.GOST_EL_SIGN_NAME);
		signature.initVerify(cert);
		signature.update(data);
		return signature.verify(sign);
	}

	/**
	 * write log
	 * 
	 * @param checkResult
	 *            прошла ли проверка
	 * @param signNum
	 *            номер подписи
	 * @param certNum
	 *            номер сертификата
	 * @param cert
	 *            сертификат
	 */
	private static void writeLog(boolean checkResult, int signNum, int certNum, X509Certificate cert) {

		if (checkResult) {
			out.append("\n");
			out.append("sign[");
			out.append(signNum);
			out.append("] - Valid signature on cert[");
			out.append(certNum);
			out.append("] (");
			out.append(cert.getSubjectX500Principal());
			out.append(")");
			validsign += 1;
		} else {
			out1.append("\n");
			out1.append("sign[");
			out1.append(signNum);
			out1.append("] - Invalid signature on cert[");
			out1.append(certNum);
			out1.append("] (");
			out1.append(cert.getSubjectX500Principal());
			out1.append(")");
		}
	}
	
	public static byte[] digestm(byte[] bytes, String digestAlgorithmName)
	        throws Exception {
	    //calculation messageDigest
	    final ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
	    final MessageDigest digest = MessageDigest.getInstance(digestAlgorithmName);
	    final DigestInputStream digestStream =
	            new DigestInputStream(stream, digest);
	    while (digestStream.available() != 0) digestStream.read();
	    return digest.digest();
	}
}
