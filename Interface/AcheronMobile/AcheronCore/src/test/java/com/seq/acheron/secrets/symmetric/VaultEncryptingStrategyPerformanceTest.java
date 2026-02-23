package com.seq.acheron.secrets.symmetric;

import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class VaultEncryptingStrategyPerformanceTest {

    /**
     * Simple concrete implementation of VaultEncryptingStrategy for testing.
     * It just sets the derivedKey passed in the constructor.
     */
    private static class TestVaultStrategy extends VaultEncryptingStrategy {

        public TestVaultStrategy(SecretKey derivedKey, boolean generateVaultKey) throws GeneralSecurityException {
            super("AES/GCM/NoPadding", generateVaultKey);
            this.derivedKey = derivedKey;
        }

        @Override
        public String toJson() {
            return "";
        }
    }

    private static SecretKey randomDerivedKey() throws GeneralSecurityException {
        byte[] keyBytes = new byte[32]; // 256-bit AES key as a fake "derivedKey"
        SecureRandom.getInstanceStrong().nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    @Test
    void compareConstructionWithAndWithoutVaultKeyGeneration() throws Exception {
        final int iterations = 1_000; // ajusta si quieres más/menos tiempo

        // 1) Create a base encryptor and export its vaultKey
        SecretKey derivedKey = randomDerivedKey();

        TestVaultStrategy base = new TestVaultStrategy(derivedKey, true);
        assertNotNull(base.getVaultKey(), "Base strategy must have a vaultKey generated");

        String encryptedVaultKey = base.exportVaultKey();

        // 2) Case 1: construct many strategies WITHOUT generating vaultKey (generateVaultKey = false)
        long startNoGen = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            TestVaultStrategy strategy = new TestVaultStrategy(derivedKey, false);
            SecretKey imported = strategy.importVaultKey(encryptedVaultKey);
            assertNotNull(imported);
        }
        long durationNoGenNs = System.nanoTime() - startNoGen;
        double durationNoGenMs = durationNoGenNs / 1_000_000.0;

        System.out.printf(
                "Case 1 (NO vaultKey generation, then import) - iterations: %d, time: %.2f ms%n",
                iterations, durationNoGenMs
        );

        // 3) Case 2: construct many strategies WITH vaultKey generation (generateVaultKey = true)
        long startWithGen = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            TestVaultStrategy strategy = new TestVaultStrategy(derivedKey, true);
            SecretKey imported = strategy.importVaultKey(encryptedVaultKey);
            assertNotNull(imported);
        }
        long durationWithGenNs = System.nanoTime() - startWithGen;
        double durationWithGenMs = durationWithGenNs / 1_000_000.0;

        System.out.printf(
                "Case 2 (WITH vaultKey generation, then import) - iterations: %d, time: %.2f ms%n",
                iterations, durationWithGenMs
        );

        // Just to avoid "no assertions" warnings; we are mainly benchmarking.
        assertNotNull(encryptedVaultKey);
    }
}
