package com.seq.acheron.secrets.symmetric;

import com.seq.acheron.vault.secrets.symmetric.PBKDF2VaultEncryptingStrategy;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class PBKDF2VaultEncryptingStrategyTest {

    private static final String MASTER_PASSWORD = "PBKDF2-Master-Password!";
    private static final String SALT_BASE64 =
            Base64.getEncoder().encodeToString("pbkdf2-salt-1234".getBytes(StandardCharsets.UTF_8));

    @Test
    void encryptThenDecrypt_withSameInstance_returnsOriginalPlaintext() throws Exception {
        PBKDF2VaultEncryptingStrategy strategy =
                new PBKDF2VaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, true);

        String plainText = "Hola, mundo secreto con AES + PBKDF2";

        String cipher = strategy.encrypt(plainText);
        String decrypted = strategy.decrypt(cipher);

        assertEquals(plainText, decrypted);

        System.out.println("[OK] PBKDF2EncryptingStrategy.encryptThenDecrypt_withSameInstance_returnsOriginalPlaintext");
    }

    @Test
    void exportAndImportVaultKey_reopenWithSameMaster_canDecryptOldData() throws Exception {
        // 1) First strategy: derive key, generate vaultKey and encrypt a message
        PBKDF2VaultEncryptingStrategy creator =
                new PBKDF2VaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, true);

        String plainText = "Mensaje protegido en la bóveda (AES + PBKDF2)";
        String cipher = creator.encrypt(plainText);

        String encryptedVaultKey = creator.exportVaultKey();

        // 2) Re-derive the same derivedKey
        PBKDF2VaultEncryptingStrategy opener =
                new PBKDF2VaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, true);

        SecretKey importedVaultKey =
                opener.importVaultKey(encryptedVaultKey);

        // 3) New instance using imported vaultKey
        PBKDF2VaultEncryptingStrategy reopener =
                new PBKDF2VaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, importedVaultKey);

        String decrypted = reopener.decrypt(cipher);

        assertEquals(plainText, decrypted);
        System.out.println("[OK] PBKDF2EncryptingStrategy.exportAndImportVaultKey_reopenWithSameMaster_canDecryptOldData");
    }

    @Test
    void importVaultKey_withWrongMasterPasswordFails() throws Exception {
        PBKDF2VaultEncryptingStrategy correct =
                new PBKDF2VaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, true);

        String encryptedVaultKey = correct.exportVaultKey();

        PBKDF2VaultEncryptingStrategy wrong =
                new PBKDF2VaultEncryptingStrategy("Wrong-Master-Password", SALT_BASE64, true);

        assertThrows(GeneralSecurityException.class, () -> {
            wrong.importVaultKey(encryptedVaultKey);
        });

        System.out.println("[OK] PBKDF2EncryptingStrategy.importVaultKey_withWrongMasterPasswordFails");
    }

    @Test
    void keysHaveExpectedLength() throws Exception {
        PBKDF2VaultEncryptingStrategy strategy =
                new PBKDF2VaultEncryptingStrategy(MASTER_PASSWORD, SALT_BASE64, true);

        assertEquals(32, strategy.getVaultKey().getEncoded().length,
                "Vault key must be 32 bytes (256 bits)");
        assertEquals(32, strategy.getDerivedKey().getEncoded().length,
                "Derived key should be 32 bytes (256 bits)");

        System.out.println("[OK] PBKDF2EncryptingStrategy.keysHaveExpectedLength");
    }
}
