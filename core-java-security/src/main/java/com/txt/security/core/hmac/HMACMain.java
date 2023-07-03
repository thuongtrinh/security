package com.txt.security.core.hmac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HMACMain {


    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        givenDataAndKeyAndAlgorithm_whenHmacWithJava();
        givenDataAndKeyAndAlgorithm_whenHmacWithApacheCommons();
        givenDataAndKeyAndAlgorithm_whenHmacWithBouncyCastle();
    }

    public static void givenDataAndKeyAndAlgorithm_whenHmacWithJava() throws NoSuchAlgorithmException, InvalidKeyException {
        //given
        String hmacSHA256Value = "7bf457f0b201e799158f21f410a780ff86aad4d549d68025780d87598bb03a23";
        String hmacSHA256Algorithm = "HmacSHA256";
        String data = "sysprotxt";
        String key = "123456";

        //when
        String result = HMACUtil.hmacWithJava(hmacSHA256Algorithm, data, key);
        System.out.println(result);
    }

    public static void givenDataAndKeyAndAlgorithm_whenHmacWithApacheCommons() {
        //given
        String hmacMD5Value = "6c44873f7d5532baedc8039904e90e33";
        String hmacMD5Algorithm = "HmacMD5";
        String data = "sysprotxt";
        String key = "123456";

        //when
        String result = HMACUtil.hmacWithApacheCommons(hmacMD5Algorithm, data, key);
        System.out.println(result);
    }

    public static void givenDataAndKeyAndAlgorithm_whenHmacWithBouncyCastle() {
        //given
        String hmacSHA512Value = "5d914f82791a788de586304d087cfe6fbfb0f09097884ff9e3f062bd4d2e80e0b21a9d340881588e248314c853f00481c4cca0cda4976b1fb71653430f26986e";
        String hmacSHA512Algorithm = "HmacSHA512";
        String data = "sysprotxt";
        String key = "123456";

        //when
        String result = HMACUtil.hmacWithBouncyCastle(hmacSHA512Algorithm, data, key);
        System.out.println(result);
    }
}
