package com.txt.security.core.digitalsignature;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class DigitalSignatureMain {

    private static String messagePath = "D:\\github\\security\\core-java-security\\src\\main\\resources\\digitalsignature\\message.txt";
    private static String senderKeyStore = "D:\\github\\security\\core-java-security\\src\\main\\resources\\digitalsignature\\sender_keystore.jks";
    private static String receiverKeyStore = "D:\\github\\security\\core-java-security\\src\\main\\resources\\digitalsignature\\receiver_keystore.jks";
    private static String storeType = "JKS";
    private static String senderAlias = "senderKeyPair";
    private static String receiverAlias = "receiverKeyPair";
    private static char[] password = "changeit".toCharArray();
    private static String signingAlgorithm = "SHA256withRSA";
    private static String hashingAlgorithm = "SHA-256";

    public static void main(String[] args) throws Exception {
        givenMessageData_whenSignWithSignatureSigning_thenVerify();
        givenMessageData_whenSignWithMessageDigestAndCipher_thenVerify();
        givenMessageData_whenSignWithSignatureSigning_thenVerifyWithMessageDigestAndCipher();
        givenMessageData_whenSignWithMessageDigestAndCipher_thenVerifyWithSignature();
    }

    public static void givenMessageData_whenSignWithSignatureSigning_thenVerify() throws Exception {
        PrivateKey privateKey = DigitalSignatureUtils.getPrivateKey(senderKeyStore, password, storeType, senderAlias);
        byte[] messageBytes = Files.readAllBytes(Paths.get(messagePath));
//        System.out.println(Base64.getEncoder().encodeToString(messageBytes));

        byte[] digitalSignature = DigitalSignatureUtils.sign(messageBytes, signingAlgorithm, privateKey);
//        System.out.println(Base64.getEncoder().encodeToString(digitalSignature));

        PublicKey publicKey = DigitalSignatureUtils.getPublicKey(receiverKeyStore, password, storeType, receiverAlias);
        boolean isCorrect = DigitalSignatureUtils.verify(messageBytes, signingAlgorithm, publicKey, digitalSignature);

        System.out.println(isCorrect);
    }

    public static void givenMessageData_whenSignWithMessageDigestAndCipher_thenVerify() throws Exception {
        PrivateKey privateKey = DigitalSignatureUtils.getPrivateKey(senderKeyStore, password, storeType, senderAlias);
        byte[] messageBytes = Files.readAllBytes(Paths.get(messagePath));

        byte[] encryptedMessageHash = DigitalSignatureUtils.signWithMessageDigestAndCipher(messageBytes, hashingAlgorithm, privateKey);

        PublicKey publicKey = DigitalSignatureUtils.getPublicKey(receiverKeyStore, password, storeType, receiverAlias);
        boolean isCorrect = DigitalSignatureUtils.verifyWithMessageDigestAndCipher(messageBytes, hashingAlgorithm, publicKey, encryptedMessageHash);

        System.out.println(isCorrect);
    }

    public static void givenMessageData_whenSignWithSignatureSigning_thenVerifyWithMessageDigestAndCipher() throws Exception {
        PrivateKey privateKey = DigitalSignatureUtils.getPrivateKey(senderKeyStore, password, storeType, senderAlias);
        byte[] messageBytes = Files.readAllBytes(Paths.get(messagePath));

        byte[] digitalSignature = DigitalSignatureUtils.sign(messageBytes, signingAlgorithm, privateKey);

        PublicKey publicKey = DigitalSignatureUtils.getPublicKey(receiverKeyStore, password, storeType, receiverAlias);
        boolean isCorrect = DigitalSignatureUtils.verifyWithMessageDigestAndCipher(messageBytes, hashingAlgorithm, publicKey, digitalSignature);

        System.out.println(isCorrect);
    }

    public static void givenMessageData_whenSignWithMessageDigestAndCipher_thenVerifyWithSignature() throws Exception {
        PrivateKey privateKey = DigitalSignatureUtils.getPrivateKey(senderKeyStore, password, storeType, senderAlias);
        byte[] messageBytes = Files.readAllBytes(Paths.get(messagePath));

        byte[] encryptedMessageHash = DigitalSignatureUtils.signWithMessageDigestAndCipher(messageBytes, hashingAlgorithm, privateKey);

        PublicKey publicKey = DigitalSignatureUtils.getPublicKey(receiverKeyStore, password, storeType, receiverAlias);
        boolean isCorrect = DigitalSignatureUtils.verify(messageBytes, signingAlgorithm, publicKey, encryptedMessageHash);

        System.out.println(isCorrect);
    }
}
