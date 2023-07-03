package com.txt.security.core.crypto.cipher.main;

import com.txt.security.core.crypto.cipher.CryptoDriver;
import com.txt.security.core.crypto.cipher.CryptoUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;

public class CryptoDriverIVMain {

    private static CryptoDriver driver = new CryptoDriver();
    private static String TEST_DATA = "Encrypt this for testing";

    public static void main(String[] args) throws GeneralSecurityException {
        givenString_whenAesEcb();
        givenString_whenAesCbc();
        givenString_whenAesCfb();
        givenString_whenAesOfb();
        givenString_whenAesCtr();
        givenString_whenAesGcm();
    }

    public static void givenString_whenAesEcb() throws GeneralSecurityException {
        SecretKey key = CryptoUtils.generateKey();
        byte[] plaintext = TEST_DATA.getBytes();
        byte[] ciphertext = driver.ecbEncrypt(key, plaintext);

        //ecbEncrypt
        System.out.println(ciphertext.toString());
        StringBuilder hexString = new StringBuilder();
        for (byte b : ciphertext) {
            hexString.append(String.format("%02x", b));
        }
        System.out.println(hexString);

        //ecbDecrypt
        byte[] decryptedtext = driver.ecbDecrypt(key, ciphertext);
        System.out.println(new String(decryptedtext));
    }

    public static void givenString_whenAesGcm() throws GeneralSecurityException {
        SecretKey key = CryptoUtils.generateKey();
        byte[] iv = CryptoUtils.getRandomIVWithSize(12);
        byte[] plaintext = (TEST_DATA).getBytes();

        byte[][] ciphertext = driver.gcmEncrypt(key, iv, plaintext);
        byte[] decryptedtext = driver.gcmDecrypt(key, ciphertext[0], ciphertext[1]);

        System.out.println(new String(decryptedtext));
    }

    public static void givenString_whenAesCbc() throws GeneralSecurityException {
        SecretKey key = CryptoUtils.generateKey();
        IvParameterSpec iv = CryptoUtils.getIVSecureRandom("AES");
        byte[] plaintext = TEST_DATA.getBytes();

        byte[] ciphertext = driver.cbcEncrypt(key, iv, plaintext);
        byte[] decryptedtext = driver.cbcDecrypt(key, iv, ciphertext);

        System.out.println(new String(decryptedtext));
    }

    public static void givenString_whenAesCfb() throws GeneralSecurityException {
        SecretKey key = CryptoUtils.generateKey();
        IvParameterSpec iv = CryptoUtils.getIVSecureRandom("AES/CFB/NoPadding");
        byte[] plaintext = TEST_DATA.getBytes();

        byte[] ciphertext = driver.cfbEncrypt(key, iv, plaintext);
        byte[] decryptedtext = driver.cfbDecrypt(key, iv, ciphertext);

        System.out.println(new String(decryptedtext));
    }

    public static void givenString_whenAesOfb() throws GeneralSecurityException {
        SecretKey key = CryptoUtils.generateKey();
        IvParameterSpec iv = CryptoUtils.getIVSecureRandom("AES/OFB32/PKCS5Padding");
        byte[] plaintext = TEST_DATA.getBytes();

        byte[] ciphertext = driver.ofbEncrypt(key, iv, plaintext);
        byte[] decryptedtext = driver.ofbDecrypt(key, iv, ciphertext);

        System.out.println(new String(decryptedtext));
    }

    public static void givenString_whenAesCtr() throws GeneralSecurityException {
        SecretKey key = CryptoUtils.generateKey();
        IvParameterSpec iv = CryptoUtils.getIVSecureRandom("AES/CTR/NoPadding");
        byte[] plaintext = TEST_DATA.getBytes();

        byte[][] ciphertext = driver.ctrEncrypt(key, iv, plaintext);
        byte[] decryptedtext = driver.ctrDecrypt(key, ciphertext[0], ciphertext[1]);

        System.out.println(new String(decryptedtext));
    }

}
