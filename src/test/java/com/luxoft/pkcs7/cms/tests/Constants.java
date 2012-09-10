/**
 * $RCSfile: Constants.java,v $
 * version $Revision: 1.5 $
 * created 26.05.2009 15:07:10 by kunina
 * last modified $Date: 2009/09/25 13:12:14 $ by $Author: kunina $
 * (C) ООО Крипто-Про 2004-2009.
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

/**
 * Константы для примеров.
 *
 * @author Copyright 2004-2009 Crypto-Pro. All rights reserved.
 * @.Version
 */
public class Constants {
/** Алгоритмы **/
/**
 * алгоритм ключа подписи: "GOST3410" или JCP.GOST_DEGREE_NAME
 */
public static final String SIGN_KEY_PAIR_ALG = "GOST3410";
/**
 * алгоритм ключа обмена: "GOST3410DH" или JCP.GOST_DH_NAME
 */
public static final String EXCH_KEY_PAIR_ALG = "GOST3410DH";
/**
 * стандарт сертификата "X509" или JCP.CERTIFICATE_FACTORY_NAME
 */
public static final String CF_ALG = "X509";
/**
 * алгоритм шифрования ГОСТ 28147-89: "GOST28147" или CryptoProvider.GOST_CIPHER_NAME
 */
public static final String CHIPHER_ALG = "GOST28147";
/**
 * алгоритм хеширования ГОСТ Р 34.11-94: "GOST3411" или JCP.GOST_DIGEST_NAME
 */
public static final String DIGEST_ALG = "GOST3411";
/**
 * алгоритм подписи ГОСТ Р 34.10-2001: "GOST3411withGOST3410EL" или
 * JCP.GOST_EL_SIGN_NAME
 */
public static final String SIGN_EL_ALG = "GOST3411withGOST3410EL";
/**
 * алгоритм подписи ГОСТ Р 34.10-2001 (используется для совеместимости с
 * криптопровайдером CryptoPro CSP): "CryptoProSignature" или
 * JCP.CRYPTOPRO_SIGN_NAME
 */
public static final String SIGN_CP_ALG = "CryptoProSignature";

/**
 * датчик случайных чисел: "CPRandom" или JCP.CP_RANDOM
 */
public static final String RANDOM_ALG = "CPRandom";

/** Параметры для работы с ключами и сертификатами **/
/**
 * тип хранилища:
 * <p/>
 * "HDImageStore" - жесткий диск
 * <p/>
 * "FloppyStore" - дискета, флешка
 * <p/>
 * "OCFStore" или "J6CFStore" - карточка
 */
public static final String KEYSTORE_TYPE = "HDImageStore";

/** Вспомогательные функции и параметры **/
/**
 * hex-string
 *
 * @param array массив данных
 * @return hex-string
 */
public static String toHexString(byte[] array) {
    final char[] hex = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
            'B', 'C', 'D', 'E', 'F'};
    StringBuffer ss = new StringBuffer(array.length * 3);
    for (int i = 0; i < array.length; i++) {
        ss.append(' ');
        ss.append(hex[(array[i] >>> 4) & 0xf]);
        ss.append(hex[array[i] & 0xf]);
    }
    return ss.toString();
}
}
