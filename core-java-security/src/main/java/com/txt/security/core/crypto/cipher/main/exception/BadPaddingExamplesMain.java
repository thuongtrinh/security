package com.txt.security.core.crypto.cipher.main.exception;

import com.txt.security.core.crypto.cipher.CryptoUtils;
import com.txt.security.core.crypto.cipher.exception.BadPaddingExamples;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class BadPaddingExamplesMain {

    private static SecretKey key;
    private static IvParameterSpec ivParameterSpec;
    private static String plainText;
    private static byte[] plainTextBytes;

    public static void main(String[] args) throws Exception {
        key = CryptoUtils.getFixedKey();

//        int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
//        System.out.println("MaxAllowedKeyLength=[" + maxKeyLen + "].");

        byte[] ivBytes = new byte[]{'K', 'e', 'y', '1', '2', '3', '4', '5', 'I', 's', 'G', 'r', 'e', 'a', 't', '!'};
        ivParameterSpec = new IvParameterSpec(ivBytes);

        plainText = "plainText for testing";
        plainTextBytes = plainText.getBytes();

        givenTwoDifferentAlgorithmPaddings_whenDecrypting_thenBadPaddingExceptionIsThrown();
        givenTwoDifferentKeys_whenDecrypting_thenBadPaddingExceptionIsThrown();
        givenTwoDifferentAlgorithms_whenDecrypting_thenBadPaddingExceptionIsThrown();
        givenSameVariablesUsedForEncryptingAndDecrypting_whenDecrypting_thenNoExceptionIsThrown();
    }

    public static void givenTwoDifferentAlgorithmPaddings_whenDecrypting_thenBadPaddingExceptionIsThrown() {
        try {
            System.out.println(BadPaddingExamples.encryptAndDecryptUsingDifferentPaddings(key, plainTextBytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void givenTwoDifferentKeys_whenDecrypting_thenBadPaddingExceptionIsThrown() {
        try {
            BadPaddingExamples.encryptAndDecryptUsingDifferentKeys(plainTextBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void givenTwoDifferentAlgorithms_whenDecrypting_thenBadPaddingExceptionIsThrown() {
        try {
            BadPaddingExamples.encryptAndDecryptUsingDifferentAlgorithms(key, ivParameterSpec, plainTextBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void givenSameVariablesUsedForEncryptingAndDecrypting_whenDecrypting_thenNoExceptionIsThrown() {
        try {
            byte[] decryptedBytes = BadPaddingExamples.encryptAndDecryptUsingSamePaddingKeyAndAlgorithm(key, plainTextBytes);
            System.out.println(new String(decryptedBytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
