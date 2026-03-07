package com.seq.acheron.vault.storables;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public final class TestKeys {

    private TestKeys() {}

    static SecretKey randomVaultKey() throws GeneralSecurityException {
        byte[] keyBytes = new byte[32]; // 256 bits AES
        SecureRandom.getInstanceStrong().nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    static String fixedSaltBase64() {
        // deterministic salt for tests
        return java.util.Base64.getEncoder()
                .encodeToString("test-salt-argon2-pbkdf2".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
