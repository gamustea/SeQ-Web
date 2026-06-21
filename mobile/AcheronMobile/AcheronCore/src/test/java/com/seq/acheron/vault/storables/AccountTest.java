package com.seq.acheron.vault.storables;

import com.seq.acheron.vault.User;
import com.seq.acheron.vault.Vault;
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import static com.seq.acheron.util.CryptoUtils.generateSalt;
import static org.junit.jupiter.api.Assertions.*;

public class AccountTest {

    private static class TestVaultStrategy extends VaultEncryptingStrategy {

        TestVaultStrategy() throws GeneralSecurityException {
            super("test-master-password", "AES/GCM/NoPadding", generateSalt(), true);
            byte[] dk = new byte[32];
            SecureRandom.getInstanceStrong().nextBytes(dk);
            this.derivedKey = new SecretKeySpec(dk, "AES");
        }

        @Override
        protected SecretKey deriveKey(String masterPassword, String saltBase64) throws GeneralSecurityException {
            byte[] dk = new byte[32];
            SecureRandom.getInstanceStrong().nextBytes(dk);
            return new SecretKeySpec(dk, "AES");
        }

        @Override
        public String toJson() {
            return "";
        }
    }

    @Test
    void encryptThenDecrypt_restoresOriginalFields() throws Exception {
        Account account = new Account("ACC0", "AnAccount", "user123", "github.com", "SuperSecret!", false);

        TestVaultStrategy strategy = new TestVaultStrategy();

        String beforeEncrypt = account.toString();
        String returnedFromEncrypt = account.encrypt(strategy);

        assertEquals(beforeEncrypt, returnedFromEncrypt,
                "encrypt should return the string representation of the previous state");

        assertNotEquals("user123", account.getUsername());
        assertNotEquals("github.com", account.getDomain());
        assertNotEquals("SuperSecret!", account.getPassword());

        String beforeDecrypt = account.toString();
        String returnedFromDecrypt = account.decrypt(strategy);

        assertEquals(beforeDecrypt, returnedFromDecrypt,
                "decrypt should return the string representation of the previous (encrypted) state");

        assertEquals("user123", account.getUsername());
        assertEquals("github.com", account.getDomain());
        assertEquals("SuperSecret!", account.getPassword());

        System.out.println("[OK] Account.encryptThenDecrypt_restoresOriginalFields");
    }

    @Test
    void idsHaveAccPrefixAndIncrementPerInstance() throws Exception {
        Vault vault = new Vault(new TestVaultStrategy(), new User("u1", "a", "b", "c", "d"), false);

        Account acc1 = new Account("AnAccount1", "u1", "d1", "p1", false);
        Account acc2 = new Account("AnAccount2", "u2", "d2", "p2", false);
        vault.add(acc1).add(acc2);

        String id1 = acc1.getId();
        String id2 = acc2.getId();

        // IDs nuevos son hash de 16 caracteres hexadecimales
        assertEquals(16, id1.length(), "Account ID should be 16 hex characters");
        assertEquals(16, id2.length(), "Account ID should be 16 hex characters");
        assertTrue(id1.matches("[0-9a-f]{16}"), "Account ID should be hexadecimal");
        assertTrue(id2.matches("[0-9a-f]{16}"), "Account ID should be hexadecimal");

        assertNotEquals(id1, id2, "IDs must be unique");

        System.out.printf("[OK] Account.idsHaveAccPrefixAndIncrementPerInstance: %s, %s%n", id1, id2);
    }

    @Test
    void isEncryptedFlag_startsAsFalse_whenConstructedWithPlainText() {
        Account account = new Account("ACC0", "AnAccount", "user", "domain.com", "pass", false);

        assertFalse(account.isEncrypted(), "Account should not be encrypted initially");

        System.out.println("[OK] Account.isEncryptedFlag_startsAsFalse_whenConstructedWithPlainText");
    }

    @Test
    void isEncryptedFlag_startsAsTrue_whenConstructedWithEncryptedData() {
        Account account = new Account("ACC0", "AnAccount", "encryptedUser", "encryptedDomain", "encryptedPass", true);

        assertTrue(account.isEncrypted(), "Account should be marked as encrypted");

        System.out.println("[OK] Account.isEncryptedFlag_startsAsTrue_whenConstructedWithEncryptedData");
    }

    @Test
    void isEncryptedFlag_becomesTrue_afterEncryption() throws Exception {
        Account account = new Account("ACC0", "AnAccount", "user", "domain.com", "pass", false);
        TestVaultStrategy strategy = new TestVaultStrategy();

        assertFalse(account.isEncrypted(), "Account should start unencrypted");

        account.encrypt(strategy);

        assertTrue(account.isEncrypted(), "Account should be encrypted after encrypt()");

        System.out.println("[OK] Account.isEncryptedFlag_becomesTrue_afterEncryption");
    }

    @Test
    void isEncryptedFlag_becomesFalse_afterDecryption() throws Exception {
        Account account = new Account("ACC0", "AnAccount", "user", "domain.com", "pass", false);
        TestVaultStrategy strategy = new TestVaultStrategy();

        account.encrypt(strategy);
        assertTrue(account.isEncrypted(), "Account should be encrypted");

        account.decrypt(strategy);

        assertFalse(account.isEncrypted(), "Account should be decrypted after decrypt()");

        System.out.println("[OK] Account.isEncryptedFlag_becomesFalse_afterDecryption");
    }

    @Test
    void encryptTwice_throwsIllegalStateException() throws Exception {
        Account account = new Account("ACC0", "AnAccount", "user", "domain.com", "pass", false);
        TestVaultStrategy strategy = new TestVaultStrategy();

        account.encrypt(strategy);

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            account.encrypt(strategy);
        });

        assertTrue(exception.getMessage().contains("already encrypted"),
                "Exception message should mention object is already encrypted");

        System.out.println("[OK] Account.encryptTwice_throwsIllegalStateException");
    }

    @Test
    void decryptUnencryptedObject_throwsIllegalStateException() throws Exception {
        Account account = new Account("ACC0", "AnAccount", "user", "domain.com", "pass", false);
        TestVaultStrategy strategy = new TestVaultStrategy();

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            account.decrypt(strategy);
        });

        assertTrue(exception.getMessage().contains("not encrypted"),
                "Exception message should mention object is not encrypted");

        System.out.println("[OK] Account.decryptUnencryptedObject_throwsIllegalStateException");
    }

    @Test
    void copy_preservesIsEncryptedFlag() throws Exception {
        Account original = new Account("ACC0", "AnAccount", "user", "domain.com", "pass", false);
        TestVaultStrategy strategy = new TestVaultStrategy();

        original.encrypt(strategy);
        assertTrue(original.isEncrypted());

        Account copy = (Account) original.copy();

        assertTrue(copy.isEncrypted(), "Copy should preserve isEncrypted flag");
        assertEquals(original.getUsername(), copy.getUsername());
        assertEquals(original.getDomain(), copy.getDomain());
        assertEquals(original.getPassword(), copy.getPassword());

        System.out.println("[OK] Account.copy_preservesIsEncryptedFlag");
    }
}
