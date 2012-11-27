package com.luxoft.pkcs7.cms;

import java.io.IOException;

import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;

import ru.CryptoPro.JCP.tools.Array;

public class BCTryDecrypt {
	
	public static void main(String[] args) throws CMSException, IOException {
		
		 byte[] buffer = Array.readFile("C:/developer/temp/test_20121116.p7m");
		
		org.bouncycastle.cms.CMSEnvelopedData data = new CMSEnvelopedData(buffer);
	}

}
