package com.txt.security.core.hash.argon;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public class HashPassword {

    public static void main(String[] args) {
        givenRawPassword_whenEncodedWithArgon2();
        givenRawPasswordAndSalt_whenArgon2AlgorithmIsUsed();
    }

    public static void givenRawPassword_whenEncodedWithArgon2() {
        System.out.println("---Implement Argon2 Hashing With Spring Security Crypto---");

        String rawPassword = "Argon2";
        Argon2PasswordEncoder arg2SpringSecurity = new Argon2PasswordEncoder(16, 32, 1, 60000, 10);
        String hashPassword = arg2SpringSecurity.encode(rawPassword);
        System.out.println(hashPassword);
        System.out.println(arg2SpringSecurity.matches(rawPassword, hashPassword));
    }

    public static void givenRawPasswordAndSalt_whenArgon2AlgorithmIsUsed() {
        System.out.println("\n---Implement Argon2 Hashing With Bouncy Castle---");

        byte[] salt = generateSalt16Byte();
        String password = "Argon2";

        int iterations = 2;
        int memLimit = 66536;
        int hashLength = 32;
        int parallelism = 1;
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(iterations)
                .withMemoryAsKB(memLimit)
                .withParallelism(parallelism)
                .withSalt(salt);

        // Argon2BytesGenerator object. This object helps to generate the password hash
        Argon2BytesGenerator generate = new Argon2BytesGenerator();
        generate.init(builder.build());
        byte[] result = new byte[hashLength];
        generate.generateBytes(password.getBytes(StandardCharsets.UTF_8), result, 0, result.length);

        // Argon2BytesGenerator to compare the result with a test hash
        Argon2BytesGenerator verifier = new Argon2BytesGenerator();
        verifier.init(builder.build());
        byte[] testHash = new byte[hashLength];
        verifier.generateBytes(password.getBytes(StandardCharsets.UTF_8), testHash, 0, testHash.length);
        System.out.println(Arrays.equals(result, testHash));
    }

    private static byte[] generateSalt16Byte() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        return salt;
    }
}
