package com.txt.security.core.secretkey;

import com.sun.tools.javac.Main;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Random;

import static javax.crypto.Cipher.ENCRYPT_MODE;

public class GeneratingSecureAESKey {

    private static final Logger logger = LoggerFactory.getLogger(Main.class);
    private static final String CIPHER = "AES";

    public static void main(String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException, InvalidKeySpecException {

        String plainText = "plainText for testing";

        System.out.println("encrypt by Random");
        encrypt(plainText, getRandomKey(CIPHER, 128));
        encrypt(plainText, getRandomKey(CIPHER, 192));
        encrypt(plainText, getRandomKey(CIPHER, 256));

        System.out.println("\nencrypt by SecureRandom");
        encrypt(plainText, getSecureRandomKey(CIPHER, 128));
        encrypt(plainText, getSecureRandomKey(CIPHER, 192));
        encrypt(plainText, getSecureRandomKey(CIPHER, 256));

        System.out.println("\nencrypt by KeyGenerator");
        encrypt(plainText, getKeyFromKeyGenerator(CIPHER, 128));
        encrypt(plainText, getKeyFromKeyGenerator(CIPHER, 192));
        encrypt(plainText, getKeyFromKeyGenerator(CIPHER, 256));

        System.out.println("\nencrypt by KeyGenerator of BasedKey and salt");
        encrypt(plainText, getPasswordBasedKey(CIPHER, 128, new char[] { 'R', 'a', 'n', 'd', 'o', 'm' }));
        encrypt(plainText, getPasswordBasedKey(CIPHER, 192, new char[] { 'R', 'a', 'n', 'd', 'o', 'm' }));
        encrypt(plainText, getPasswordBasedKey(CIPHER, 256, new char[] { 'R', 'a', 'n', 'd', 'o', 'm' }));
    }

    private static void encrypt(String plainText, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(ENCRYPT_MODE, key);
        byte[] cipherTextBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        System.out.println(Base64.getEncoder().encodeToString(cipherTextBytes));
    }

    private static Key getRandomKey(String cipher, int keySize) {
        byte[] randomKeyBytes = new byte[keySize / 8];
        Random random = new Random();
        random.nextBytes(randomKeyBytes);
        return new SecretKeySpec(randomKeyBytes, cipher);
    }

    private static Key getSecureRandomKey(String cipher, int keySize) {
        byte[] secureRandomKeyBytes = new byte[keySize / 8];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(secureRandomKeyBytes);
        return new SecretKeySpec(secureRandomKeyBytes, cipher);
    }

    private static Key getKeyFromKeyGenerator(String cipher, int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(cipher);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    private static Key getPasswordBasedKey(String cipher, int keySize, char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = new byte[100];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 100000, keySize);
        SecretKey pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);
        return new SecretKeySpec(pbeKey.getEncoded(), cipher);
    }
}
