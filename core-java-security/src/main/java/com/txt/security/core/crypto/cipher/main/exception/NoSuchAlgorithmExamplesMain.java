package com.txt.security.core.crypto.cipher.main.exception;

import com.txt.security.core.crypto.cipher.exception.NoSuchAlgorithmExamples;

import javax.crypto.Cipher;


public class NoSuchAlgorithmExamplesMain {

    public static void main(String[] args) {
        whenInitingCipherWithUnknownAlgorithm_thenNoSuchAlgorithmExceptionIsThrown();
        whenInitingCipherWithUnknownAlgorithmMode_thenNoSuchAlgorithmExceptionIsThrown();
        whenInitingCipherWithUnknownPadding_thenNoSuchAlgorithmExceptionIsThrown();
        whenInitingCipherWithValidAlgorithm_thenCipherInstanceIsReturned();
    }

    public static void whenInitingCipherWithUnknownAlgorithm_thenNoSuchAlgorithmExceptionIsThrown() {
        try {
            NoSuchAlgorithmExamples.getCipherInstanceWithBadAlgorithm();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void whenInitingCipherWithUnknownAlgorithmMode_thenNoSuchAlgorithmExceptionIsThrown() {
        try {
            NoSuchAlgorithmExamples.getCipherInstanceWithBadAlgorithmMode();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void whenInitingCipherWithUnknownPadding_thenNoSuchAlgorithmExceptionIsThrown() {
        try {
            NoSuchAlgorithmExamples.getCipherInstanceWithBadPadding();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void whenInitingCipherWithValidAlgorithm_thenCipherInstanceIsReturned() {
        try {
            Cipher cipher = NoSuchAlgorithmExamples.getCipherInstanceWithValidAlgorithm();
            System.out.println(cipher.getAlgorithm());
            System.out.println(cipher);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
