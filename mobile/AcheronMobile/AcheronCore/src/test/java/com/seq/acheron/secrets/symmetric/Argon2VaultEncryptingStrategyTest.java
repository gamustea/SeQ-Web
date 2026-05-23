package com.seq.acheron.secrets.symmetric;

import com.seq.acheron.vault.secrets.symmetric.Argon2VaultEncryptingStrategy;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class Argon2VaultEncryptingStrategyTest {

    private static final String MASTER_PASSWORD = "SuperSecret123!";
    private static final String SALT_BASE64 =
            Base64.getEncoder().encodeToString("argon2-salt-1234".getBytes(StandardCharsets.UTF_8));

    @Test
    void encryptThenDecrypt_withSameInstance_returnsOriginalPlaintext() throws Exception {
        Argon2VaultEncryptingStrategy strategy =
                new Argon2VaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, true);

        String plainText = "Hola, mundo secreto con AES + Argon2";

        String cipher = strategy.encrypt(plainText);
        String decrypted = strategy.decrypt(cipher);

        assertEquals(plainText, decrypted);

        System.out.println("[OK] AESEncryptingStrategy.encryptThenDecrypt_withSameInstance_returnsOriginalPlaintext");
    }

    @Test
    void exportAndImportVaultKey_reopenWithSameMaster_canDecryptOldData() throws Exception {
        // 1) Create first strategy, derive key, generate vaultKey and encrypt a message
        Argon2VaultEncryptingStrategy creator =
                new Argon2VaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, true);

        String plainText = "Mensaje protegido en la bóveda (AES + Argon2)";
        String cipher = creator.encrypt(plainText);

        String encryptedVaultKey = creator.exportVaultKey();

        // 2) Simulate reopening the vault: derive the same derivedKey again
        Argon2VaultEncryptingStrategy opener =
                new Argon2VaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, true);

        SecretKey importedVaultKey =
                opener.importVaultKey(encryptedVaultKey);

        // 3) Create a new strategy instance using the imported vaultKey
        Argon2VaultEncryptingStrategy reopener =
                new Argon2VaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, importedVaultKey);

        String decrypted = reopener.decrypt(cipher);

        assertEquals(plainText, decrypted);
        System.out.println("[OK] AESEncryptingStrategy.exportAndImportVaultKey_reopenWithSameMaster_canDecryptOldData");
    }

    @Test
    void importVaultKey_withWrongMasterPasswordFails() throws Exception {
        Argon2VaultEncryptingStrategy correct =
                new Argon2VaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, true);

        String encryptedVaultKey = correct.exportVaultKey();

        // Wrong master password → wrong derivedKey
        Argon2VaultEncryptingStrategy wrong =
                new Argon2VaultEncryptingStrategy("WrongMasterPassword", SALT_BASE64, true);

        assertThrows(GeneralSecurityException.class, () -> {
            wrong.importVaultKey(encryptedVaultKey);
        });

        System.out.println("[OK] AESEncryptingStrategy.importVaultKey_withWrongMasterPasswordFails");
    }

    @Test
    void keysHaveExpectedLength() throws Exception {
        Argon2VaultEncryptingStrategy strategy =
                new Argon2VaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, true);

        assertEquals(32, strategy.getVaultKey().getEncoded().length,
                "Vault key must be 32 bytes (256 bits)");
        assertEquals(32, strategy.getDerivedKey().getEncoded().length,
                "Derived key should be 32 bytes (256 bits)");

        System.out.println("[OK] AESEncryptingStrategy.keysHaveExpectedLength");
    }
}
