package com.txt.security.core.crypto.cipher.exception;

import com.txt.security.core.crypto.cipher.CryptoUtils;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class IllegalBlockSizeExamples {

    public static byte[] encryptWithoutPadding(SecretKey key, byte[] plainTextBytes) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(plainTextBytes);
    }

    public static byte[] decryptTextThatIsNotEncrypted(SecretKey key) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        // note that this text is not encrypted at any point in this method.
        String sampleText = "sampleText";
        byte[] unencryptedCipherTextBytes = sampleText.getBytes();

        return CryptoUtils.decryptWithPadding(key, unencryptedCipherTextBytes);
    }
}
