package com.txt.security.core.aes;

import com.txt.security.core.aes.model.Student;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class AESMain {

    public static void main(String[] args) throws Exception {
        givenString_whenEncrypt();
        givenFile_whenEncrypt();
        givenObject_whenEncrypt();
        givenPassword_whenEncrypt();
    }

    private static void givenString_whenEncrypt() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {

        System.out.println("\n1. AESUtil String encrypt/decrypt");

        // given
        String input = "sysprotxt";
        SecretKey key = AESUtil.generateKey(128);
        IvParameterSpec ivParameterSpec = AESUtil.generateIv();
        String algorithm = "AES/CBC/PKCS5Padding";

        // when
        String cipherText = AESUtil.encrypt(algorithm, input, key, ivParameterSpec);
        String plainText = AESUtil.decrypt(algorithm, cipherText, key, ivParameterSpec);

        System.out.println(plainText);
    }

    private static void givenFile_whenEncrypt() throws NoSuchAlgorithmException, IOException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {

        System.out.println("\n2. AESUtil File encrypt/decrypt");

        // given
        SecretKey key = AESUtil.generateKey(128);
        String algorithm = "AES/CBC/PKCS5Padding";
        IvParameterSpec ivParameterSpec = AESUtil.generateIv();
        File inputFile = Paths.get("D:\\github\\security\\core-java-security\\src\\main\\resources\\files\\syspro.txt").toFile();
        File encryptedFile = new File("syspro.encrypted");
        File decryptedFile = new File("document.decrypted");

        // when
        AESUtil.encryptFile(algorithm, key, ivParameterSpec, inputFile, encryptedFile);
        AESUtil.decryptFile(algorithm, key, ivParameterSpec, encryptedFile, decryptedFile);

        // then
        System.out.println("inputFile: " + inputFile);
        System.out.println("decryptedFile: " + decryptedFile);

        encryptedFile.deleteOnExit();
        decryptedFile.deleteOnExit();
    }

    private static void givenObject_whenEncrypt()
            throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, IOException, BadPaddingException,
            ClassNotFoundException {

        System.out.println("\n3. AESUtil Object encrypt/decrypt");

        // given
        Student student = new Student("sysprotxt", 20);
        SecretKey key = AESUtil.generateKey(128);
        IvParameterSpec ivParameterSpec = AESUtil.generateIv();
        String algorithm = "AES/CBC/PKCS5Padding";

        // when
        SealedObject sealedObject = AESUtil.encryptObject(algorithm, student, key, ivParameterSpec);
        Student object = (Student) AESUtil.decryptObject(algorithm, sealedObject, key, ivParameterSpec);

        // then
        System.out.println(student);
        System.out.println(object);
        System.out.println(student.equals(object));
    }

    private static void givenPassword_whenEncrypt()
            throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {

        System.out.println("\n4. AESUtil data encrypt/decrypt with Password");

        // given
        String plainText = "www.sysprotxt.com";
        String password = "syspro123";
        String salt = "12345678";
        IvParameterSpec ivParameterSpec = AESUtil.generateIv();
        SecretKey key = AESUtil.getKeyFromPassword(password, salt);

        // when
        String cipherText = AESUtil.encryptPasswordBased(plainText, key, ivParameterSpec);
        String decryptedCipherText = AESUtil.decryptPasswordBased(cipherText, key, ivParameterSpec);

        System.out.println(plainText);
        System.out.println(decryptedCipherText);
    }
}
