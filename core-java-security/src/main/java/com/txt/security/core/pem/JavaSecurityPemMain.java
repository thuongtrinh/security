package com.txt.security.core.pem;

import java.io.File;
import java.nio.file.Paths;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class JavaSecurityPemMain {

    public static void main(String[] args) throws Exception {
        whenReadPublicKeyFromPEMFile();
        whenReadPrivateKeyFromPEMFile();
    }

    public static void whenReadPublicKeyFromPEMFile() throws Exception {
        File pemFile = Paths.get("D:\\github\\security\\core-java-security\\src\\main\\resources\\pem\\public-key.pem").toFile();
        RSAPublicKey publicKey = JavaSecurityPemUtils.readX509PublicKey(pemFile);

        System.out.println(publicKey.getFormat());
        System.out.println(publicKey.getAlgorithm());
    }

    public static void whenReadPrivateKeyFromPEMFile() throws Exception {
        File pemFile = Paths.get("D:\\github\\security\\core-java-security\\src\\main\\resources\\pem\\private-key-pkcs8.pem").toFile();
        RSAPrivateKey privateKey = JavaSecurityPemUtils.readPKCS8PrivateKey(pemFile);

        System.out.println(privateKey.getFormat());
        System.out.println(privateKey.getAlgorithm());
    }
}
