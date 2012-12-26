package org.lu.pkcs7.cms;

import java.io.IOException;

import ru.CryptoPro.JCP.tools.Array;

public class Base64Convert {

	/**
	 * @param args
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		
		byte[] buffer = Array.readFile("C:/developer/temp/bak_contact/Key#2_2011/OpenKeys/cert_16464.pem1");
		
		buffer = javax.xml.bind.DatatypeConverter.parseBase64Binary(new String(buffer));
		
		Array.writeFile("C:/developer/temp/bak_contact/Key#2_2011/OpenKeys/cert_16464.pem_der", buffer);
	}

}
