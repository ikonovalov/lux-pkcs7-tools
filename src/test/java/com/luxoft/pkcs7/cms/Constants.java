package com.luxoft.pkcs7.cms;

import ru.CryptoPro.JCP.JCP;

public interface Constants {

	public static final String STR_CMS_OID_DATA = "1.2.840.113549.1.7.1";

	public static final String STR_CMS_OID_SIGNED = "1.2.840.113549.1.7.2";

	public static final String STR_CMS_OID_ENVELOPED = "1.2.840.113549.1.7.3";

	public static final String STR_CMS_OID_CONT_TYP_ATTR = "1.2.840.113549.1.9.3";

	public static final String STR_CMS_OID_DIGEST_ATTR = "1.2.840.113549.1.9.4";

	public static final String STR_CMS_OID_SIGN_TYM_ATTR = "1.2.840.113549.1.9.5";

	public static final String STR_CMS_OID_TS = "1.2.840.113549.1.9.16.1.4";

	public static final String DIGEST_OID = JCP.GOST_DIGEST_OID;

	public static final String SIGN_OID = JCP.GOST_EL_KEY_OID;

	public static final String STORE_TYPE = "HDImageStore";

	public static final String KEY_ALG_NAME = JCP.GOST_DH_NAME;

	public static final String DIGEST_ALG_NAME = JCP.GOST_DIGEST_NAME;

	public static final String SEC_KEY_ALG_NAME = "GOST28147";

}
