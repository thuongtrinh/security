package com.txt.security.core.secretkeyandstringconversion;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class ConversionClassUtilMain {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        givenPasswordAndSalt_whenCreateSecreKeyCheckConversion();
    }

    public static void givenPasswordAndSalt_whenCreateSecreKeyCheckConversion() throws NoSuchAlgorithmException, InvalidKeySpecException {
        // given
        String password = "Syspro@2023";
        String salt = "@$#SysPro@#^$*";

        // when
        SecretKey encodedKey = ConversionClassUtil.getKeyFromPassword(password, salt);
        String encodedString = ConversionClassUtil.convertSecretKeyToString(encodedKey);
        SecretKey decodeKey = ConversionClassUtil.convertStringToSecretKeyto(encodedString);

        System.out.println(encodedKey);
        System.out.println(encodedString);
        System.out.println(decodeKey);
    }
}
