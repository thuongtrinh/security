package com.txt.security.core.crypto.sha1;

import com.google.common.hash.Hashing;
import org.apache.commons.codec.digest.DigestUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HexRepresentationSha1Digest {

    static String input = "Hello world";
    String expectedHexValue = "7b502c3a1f48c8609ae212cdfb639dee39673f5e";

    public static void main(String[] args) throws NoSuchAlgorithmException {
        givenMessageDigest_whenUpdatingWithData();
        givenDigestUtils_whenCalculatingSHA1Hex();
        givenHashingLibrary_whenCalculatingSHA1Hash();
    }

    private static void givenMessageDigest_whenUpdatingWithData() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        byte[] digest = md.digest();

        for (byte b : digest) {
            hexString.append(String.format("%02x", b));
        }

        System.out.println(hexString);
    }

    public static void givenDigestUtils_whenCalculatingSHA1Hex() {
        System.out.println(DigestUtils.sha1Hex(input));
    }

    public static void givenHashingLibrary_whenCalculatingSHA1Hash() {
        System.out.println(Hashing.sha1().hashString(input, StandardCharsets.UTF_8));
        System.out.println(Hashing.sha256().hashString(input, StandardCharsets.UTF_8));
        System.out.println(Hashing.sha384().hashString(input, StandardCharsets.UTF_8));
        System.out.println(Hashing.sha512().hashString(input, StandardCharsets.UTF_8));
    }
}
