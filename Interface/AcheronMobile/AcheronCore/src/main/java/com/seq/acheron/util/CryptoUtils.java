package com.seq.acheron.util;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utility class for cryptographic operations.
 */
public final class CryptoUtils {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int DEFAULT_SALT_LENGTH = 16; // 128 bits

    private CryptoUtils() {
        // Utility class, no instantiation
    }

    /**
     * Generates a cryptographically secure random salt.
     *
     * @return Base64-encoded string representation of the salt (16 bytes)
     */
    public static String generateSalt() {
        return generateSalt(DEFAULT_SALT_LENGTH);
    }

    /**
     * Generates a cryptographically secure random salt of specified length.
     *
     * @param length length in bytes (recommended: 16-32)
     * @return Base64-encoded string representation of the salt
     * @throws IllegalArgumentException if length is less than 16
     */
    public static String generateSalt(int length) {
        if (length < 16) {
            throw new IllegalArgumentException("Salt length must be at least 16 bytes (128 bits)");
        }

        byte[] salt = new byte[length];
        SECURE_RANDOM.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Generates a salt and returns it as a hexadecimal string.
     * Useful if you prefer readability over compactness.
     *
     * @return Hex-encoded string representation of the salt
     */
    public static String generateSaltHex() {
        return generateSaltHex(DEFAULT_SALT_LENGTH);
    }

    /**
     * Generates a salt of specified length as hexadecimal.
     *
     * @param length length in bytes
     * @return Hex-encoded string (2 chars per byte)
     */
    public static String generateSaltHex(int length) {
        if (length < 16) {
            throw new IllegalArgumentException("Salt length must be at least 16 bytes");
        }

        byte[] salt = new byte[length];
        SECURE_RANDOM.nextBytes(salt);

        StringBuilder hex = new StringBuilder(length * 2);
        for (byte b : salt) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
}
