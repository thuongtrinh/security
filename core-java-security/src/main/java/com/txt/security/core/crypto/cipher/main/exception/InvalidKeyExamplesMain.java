package com.txt.security.core.crypto.cipher.main.exception;

import com.txt.security.core.crypto.cipher.CryptoUtils;
import com.txt.security.core.crypto.cipher.exception.InvalidKeyExamples;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;

public class InvalidKeyExamplesMain {

    private static SecretKey key;
    private static String plainText;
    private static byte[] cipherTextBytes;

    public static void main(String[] args) throws GeneralSecurityException {
        key = CryptoUtils.getFixedKey();
        byte[] ivBytes = new byte[]{'K', 'e', 'y', '1', '2', '3', '4', '5', 'I', 's', 'G', 'r', 'e', 'a', 't', '!'};
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        plainText = "plainText for testing";
        byte[] plainTextBytes = plainText.getBytes();
        cipherTextBytes = cipher.doFinal(plainTextBytes);

        givenTextEncryptedWithCBC_whenDecryptingWithNoIv_thenInvalidKeyExceptionIsThrown();
        givenTextEncryptedWithCBC_whenDecryptingWithIv_thenTextIsDecrypted();
        whenKeyIsTooShort_thenInvalidKeyExceptionIsThrown();
        whenKeyIsTooLong_thenInvalidKeyExceptionIsThrown();
    }

    public static void givenTextEncryptedWithCBC_whenDecryptingWithNoIv_thenInvalidKeyExceptionIsThrown() {
        try {
            InvalidKeyExamples.decryptUsingCBCWithNoIV(key, cipherTextBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void givenTextEncryptedWithCBC_whenDecryptingWithIv_thenTextIsDecrypted() {
        try {
            byte[] decryptedBytes = InvalidKeyExamples.decryptUsingCBCWithIV(key, cipherTextBytes);
            System.out.println(new String(decryptedBytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void whenKeyIsTooShort_thenInvalidKeyExceptionIsThrown() {
        try {
            InvalidKeyExamples.encryptWithKeyTooShort();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void whenKeyIsTooLong_thenInvalidKeyExceptionIsThrown() {
        try {
            InvalidKeyExamples.encryptWithKeyTooLong();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
