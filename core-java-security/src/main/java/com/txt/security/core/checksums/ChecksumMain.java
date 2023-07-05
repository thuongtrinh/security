package com.txt.security.core.checksums;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ChecksumMain {

    public static void main(String[] args) throws IOException {
        givenByteArray_whenChecksumCreated();
        givenTwoDifferentStrings_whenChecksumCreated();
        givenInputString_whenChecksumCreated();
    }

    private static void givenByteArray_whenChecksumCreated() {
        byte[] arr = new byte[]{0, 10, 21, 20, 35, 40, 120, 56, 72, 22};
        long checksum = ChecksumUtils.getChecksumCRC32(arr);
        System.out.println(checksum + "\n");
    }

    private static void givenTwoDifferentStrings_whenChecksumCreated() {
        String plumless = "plumless";
        String buckeroo = "buckeroo";

        long plumlessChecksum = ChecksumUtils.getChecksumCRC32(plumless.getBytes());
        long buckerooChecksum = ChecksumUtils.getChecksumCRC32(buckeroo.getBytes());

        System.out.println(plumlessChecksum);
        System.out.println(buckerooChecksum + "\n");
    }

    private static void givenInputString_whenChecksumCreated() throws IOException {
        byte[] arr = new byte[]{0, 10, 21, 20, 35, 40, 120, 56, 72, 22};
        InputStream inputStream = new ByteArrayInputStream(arr);
        long checksum = ChecksumUtils.getChecksumCRC32(inputStream, 10);

        System.out.println(checksum + "\n");
    }
}
