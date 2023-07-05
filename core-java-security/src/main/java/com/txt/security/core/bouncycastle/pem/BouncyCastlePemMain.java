package com.txt.security.core.bouncycastle.pem;

import java.io.File;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class BouncyCastlePemMain {

    public static void main(String[] args) throws Exception {
        whenReadPublicKeyFromPEMFile();
        whenReadPrivateKeyFromPEMFile();
    }

    public static void whenReadPublicKeyFromPEMFile() throws Exception {
        File pemFile = new File(BouncyCastlePemMain.class.getResource("/pem/public-key.pem").getFile());

        RSAPublicKey publicKey1 = BouncyCastlePemUtils.readX509PublicKey(pemFile);
        RSAPublicKey publicKey2 = BouncyCastlePemUtils.readX509PublicKeySecondApproach(pemFile);

        System.out.println(publicKey1.getFormat());
        System.out.println(publicKey1.getAlgorithm());
        System.out.println(publicKey2.getFormat());
        System.out.println(publicKey2.getAlgorithm());
    }

    public static void whenReadPrivateKeyFromPEMFile() throws Exception {
        File pemFile = new File(BouncyCastlePemMain.class.getResource("/pem/private-key-pkcs8.pem").getFile());

        RSAPrivateKey privateKey1 = BouncyCastlePemUtils.readPKCS8PrivateKey(pemFile);
        RSAPrivateKey privateKey2 = BouncyCastlePemUtils.readPKCS8PrivateKeySecondApproach(pemFile);

        System.out.println(privateKey1.getFormat());
        System.out.println(privateKey1.getAlgorithm());
        System.out.println(privateKey2.getFormat());
        System.out.println(privateKey2.getAlgorithm());
    }
}
