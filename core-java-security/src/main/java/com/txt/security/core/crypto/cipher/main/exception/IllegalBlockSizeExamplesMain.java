package com.txt.security.core.crypto.cipher.main.exception;


import com.txt.security.core.crypto.cipher.CryptoUtils;
import com.txt.security.core.crypto.cipher.exception.IllegalBlockSizeExamples;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class IllegalBlockSizeExamplesMain {

    private static SecretKey key;
    private static byte[] plainTextBytes;
    private static String plainText;

    public static void main(String[] args) throws GeneralSecurityException {
        key = CryptoUtils.getFixedKey();
        plainText = "plainText for testing";
        plainTextBytes = plainText.getBytes();

        whenEncryptingPlainTextWithoutPadding_thenIllegalBlockSizeExceptionIsThrown();
        whenDecryptingCipherTextThatWasNotEncrypted_thenIllegalBlockSizeExceptionIsThrown();
        whenEncryptingAndDecryptingWithPadding_thenNoExceptionThrown();
    }

    public static void whenEncryptingPlainTextWithoutPadding_thenIllegalBlockSizeExceptionIsThrown() {
        try {
            IllegalBlockSizeExamples.encryptWithoutPadding(key, plainTextBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void whenDecryptingCipherTextThatWasNotEncrypted_thenIllegalBlockSizeExceptionIsThrown() {
        try {
            IllegalBlockSizeExamples.decryptTextThatIsNotEncrypted(key);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void whenEncryptingAndDecryptingWithPadding_thenNoExceptionThrown() throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        byte[] cipherTextBytes = CryptoUtils.encryptWithPadding(key, plainTextBytes);
        byte[] decryptedBytes = CryptoUtils.decryptWithPadding(key, cipherTextBytes);

        System.out.println(new String(decryptedBytes));
    }
}
