package com.seq.acheron.secrets.symmetric;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class AESVaultEncryptingStrategyTest {

    private static final String MASTER_PASSWORD = "SuperSecret123!";
    private static final String SALT_BASE64 =
            Base64.getEncoder().encodeToString("argon2-salt-1234".getBytes(StandardCharsets.UTF_8));

    @Test
    void encryptThenDecrypt_withSameInstance_returnsOriginalPlaintext() throws Exception {
        AESVaultEncryptingStrategy strategy =
                new AESVaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, true);

        String plainText = "Hola, mundo secreto con AES + Argon2";

        String cipher = strategy.encrypt(plainText);
        String decrypted = strategy.decrypt(cipher);

        assertEquals(plainText, decrypted);

        System.out.println("[OK] AESEncryptingStrategy.encryptThenDecrypt_withSameInstance_returnsOriginalPlaintext");
    }

    @Test
    void exportAndImportVaultKey_reopenWithSameMaster_canDecryptOldData() throws Exception {
        // 1) Create first strategy, derive key, generate vaultKey and encrypt a message
        AESVaultEncryptingStrategy creator =
                new AESVaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, true);

        String plainText = "Mensaje protegido en la bóveda (AES + Argon2)";
        String cipher = creator.encrypt(plainText);

        String encryptedVaultKey = creator.exportVaultKey();

        // 2) Simulate reopening the vault: derive the same derivedKey again
        AESVaultEncryptingStrategy opener =
                new AESVaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, true);

        SecretKey importedVaultKey =
                opener.importVaultKey(encryptedVaultKey);

        // 3) Create a new strategy instance using the imported vaultKey
        AESVaultEncryptingStrategy reopener =
                new AESVaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, importedVaultKey);

        String decrypted = reopener.decrypt(cipher);

        assertEquals(plainText, decrypted);
        System.out.println("[OK] AESEncryptingStrategy.exportAndImportVaultKey_reopenWithSameMaster_canDecryptOldData");
    }

    @Test
    void importVaultKey_withWrongMasterPasswordFails() throws Exception {
        AESVaultEncryptingStrategy correct =
                new AESVaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, true);

        String encryptedVaultKey = correct.exportVaultKey();

        // Wrong master password → wrong derivedKey
        AESVaultEncryptingStrategy wrong =
                new AESVaultEncryptingStrategy("WrongMasterPassword", SALT_BASE64, true);

        assertThrows(GeneralSecurityException.class, () -> {
            wrong.importVaultKey(encryptedVaultKey);
        });

        System.out.println("[OK] AESEncryptingStrategy.importVaultKey_withWrongMasterPasswordFails");
    }

    @Test
    void keysHaveExpectedLength() throws Exception {
        AESVaultEncryptingStrategy strategy =
                new AESVaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, true);

        assertEquals(32, strategy.getVaultKey().getEncoded().length,
                "Vault key must be 32 bytes (256 bits)");
        assertEquals(32, strategy.getDerivedKey().getEncoded().length,
                "Derived key should be 32 bytes (256 bits)");

        System.out.println("[OK] AESEncryptingStrategy.keysHaveExpectedLength");
    }
}
