package com.seq.acheron.util;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * Utility class for cryptographic operations.
 */
public final class CryptoUtils {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int DEFAULT_SALT_LENGTH = 16; // 128 bits

    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS    = "0123456789";
    private static final String SPECIALS  = "!@#$%^&*()-_=+[]{}|;:,.<>?";
    private static final String ALL_CHARS = UPPERCASE + LOWERCASE + DIGITS + SPECIALS;


    /**
     * Generates a secure password of the requested length.
     * Guarantees at least one character of each category and shuffles randomly.
     *
     * @param length desired length (12 or more recommended)
     * @return the generated password
     */
    public static String generatePassword(int length) {
        if (length < 4) {
            throw new IllegalArgumentException("Minimum length is 4.");
        }

        List<Character> chars = new ArrayList<>(length);

        // Guarantee at least one of each type
        chars.add(UPPERCASE.charAt(SECURE_RANDOM.nextInt(UPPERCASE.length())));
        chars.add(LOWERCASE.charAt(SECURE_RANDOM.nextInt(LOWERCASE.length())));
        chars.add(DIGITS   .charAt(SECURE_RANDOM.nextInt(DIGITS.length())));
        chars.add(SPECIALS .charAt(SECURE_RANDOM.nextInt(SPECIALS.length())));

        // Fill the rest with random characters from the full pool
        for (int i = 4; i < length; i++) {
            chars.add(ALL_CHARS.charAt(SECURE_RANDOM.nextInt(ALL_CHARS.length())));
        }

        /* Shuffle to avoid predictable positions (e.g. the special char always last) */
        Collections.shuffle(chars, SECURE_RANDOM);

        StringBuilder sb = new StringBuilder(length);
        for (char c : chars) sb.append(c);
        return sb.toString();
    }

    /**
     * Overload using the default length (16 characters).
     */
    public static String generatePassword() {
        return generatePassword(16);
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
        return toHex(salt);
    }

    /**
     * Encodes a byte array as a lowercase hexadecimal string (2 chars per byte).
     *
     * @param bytes the bytes to encode
     * @return the hex representation
     */
    public static String toHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    /**
     * Computes the SHA-256 digest of the UTF-8 bytes of {@code value} and returns
     * it as a lowercase hexadecimal string.
     *
     * @param value the input to hash
     * @return the SHA-256 digest as hex
     * @throws GeneralSecurityException if SHA-256 is unavailable
     */
    public static String sha256Hex(String value) throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
        return toHex(hash);
    }

    /**
     * Compares two strings in (approximate) constant time to mitigate timing
     * attacks. Both strings must be non-null.
     */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        if (a.length() != b.length()) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
