package com.luxoft.pkcs7.cms;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import com.luxoft.pki.tools.CryptoUtils;

public class CheckBase64 {

	/**
	 * @param args
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		File f = new File("C:\\developer\\temp\\V002181221.p7m");
		FileInputStream fis = new FileInputStream(f);
		byte[] buffer = new byte[(int) f.length()];
		fis.read(buffer);
		fis.close();
		boolean isB64 = CryptoUtils.isBase64(buffer);
		System.out.println("isB64=" + isB64);
	}

}
