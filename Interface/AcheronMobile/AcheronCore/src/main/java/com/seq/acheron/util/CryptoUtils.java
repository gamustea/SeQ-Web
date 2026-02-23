package com.seq.acheron.util;

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
     * Genera una contraseña segura de longitud personalizada.
     * Garantiza al menos un carácter de cada categoría y mezcla aleatoriamente.
     *
     * @param length longitud deseada (mínimo 12 recomendado)
     * @return contraseña generada
     */
    public static String generatePassword(int length) {
        if (length < 4) {
            throw new IllegalArgumentException("La longitud mínima es 4.");
        }

        List<Character> chars = new ArrayList<>(length);

        // Garantiza al menos uno de cada tipo
        chars.add(UPPERCASE.charAt(SECURE_RANDOM.nextInt(UPPERCASE.length())));
        chars.add(LOWERCASE.charAt(SECURE_RANDOM.nextInt(LOWERCASE.length())));
        chars.add(DIGITS   .charAt(SECURE_RANDOM.nextInt(DIGITS.length())));
        chars.add(SPECIALS .charAt(SECURE_RANDOM.nextInt(SPECIALS.length())));

        // Rellena el resto con caracteres aleatorios del pool completo
        for (int i = 4; i < length; i++) {
            chars.add(ALL_CHARS.charAt(SECURE_RANDOM.nextInt(ALL_CHARS.length())));
        }

        /* Mezcla para evitar posiciones predecibles (ej.: especial siempre al final) */
        Collections.shuffle(chars, SECURE_RANDOM);

        StringBuilder sb = new StringBuilder(length);
        for (char c : chars) sb.append(c);
        return sb.toString();
    }

    /**
     * Sobrecarga con longitud por defecto (16 caracteres).
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

        StringBuilder hex = new StringBuilder(length * 2);
        for (byte b : salt) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
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
