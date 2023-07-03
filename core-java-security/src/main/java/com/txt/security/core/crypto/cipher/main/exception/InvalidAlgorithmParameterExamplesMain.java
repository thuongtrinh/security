package com.txt.security.core.crypto.cipher.main.exception;

import com.txt.security.core.crypto.cipher.CryptoUtils;
import com.txt.security.core.crypto.cipher.exception.InvalidAlgorithmParameterExamples;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;

public class InvalidAlgorithmParameterExamplesMain {

    private static SecretKey key;
    private static String plainText;

    public static void main(String[] args) throws GeneralSecurityException {
        key = CryptoUtils.getFixedKey();
        plainText = "plainText for testing";

        givenIvIsTooShort_whenEncryptingUsingCBC_thenInvalidAlgorithmParameterExceptionIsThrown();
        givenIvIsTooLong_whenEncryptingUsingCBC_thenInvalidAlgorithmParameterExceptionIsThrown();
        givenIvIsCorrectSize_whenEncryptingUsingCBC_thenNoExceptionIsThrown();
    }

    public static void givenIvIsTooShort_whenEncryptingUsingCBC_thenInvalidAlgorithmParameterExceptionIsThrown() {
        try {
            byte[] ivBytes = new byte[]{'K', 'e', 'y', '1', '2', '3', '4', '5', 'I', 's', 'G', 'r', 'e', 'a', 't'};
//            byte[] ivBytes = new byte[]{'K', 'e', 'y', '1', '2', '3', '4', '5', 'I', 's', 'G', 'r', 'e', 'a', 't', '!'};  //correct: 16 bytes long
            InvalidAlgorithmParameterExamples.encryptUsingIv(key, ivBytes, plainText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void givenIvIsTooLong_whenEncryptingUsingCBC_thenInvalidAlgorithmParameterExceptionIsThrown() {
        try {
            byte[] ivBytes = new byte[]{'K', 'e', 'y', '1', '2', '3', '4', '5', 'I', 's', 'G', 'r', 'e', 'a', 't', '!', '0'};
            InvalidAlgorithmParameterExamples.encryptUsingIv(key, ivBytes, plainText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void givenIvIsCorrectSize_whenEncryptingUsingCBC_thenNoExceptionIsThrown() throws GeneralSecurityException {
        byte[] ivBytes = new byte[]{'K', 'e', 'y', '1', '2', '3', '4', '5', 'I', 's', 'G', 'r', 'e', 'a', 't', '!'};
        byte[] cipherTextBytes = InvalidAlgorithmParameterExamples.encryptUsingIv(key, ivBytes, plainText);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(cipherTextBytes);

        System.out.println(new String(decryptedBytes));
    }
}
