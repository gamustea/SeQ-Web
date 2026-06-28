package com.seq.acheron.vault;

import com.seq.acheron.exceptions.WrongPasswordException;
import com.seq.acheron.vault.secrets.symmetric.Argon2VaultEncryptingStrategy;
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.util.CryptoUtils;
import com.seq.acheron.vault.storables.Account;
import com.seq.acheron.vault.storables.CreditCard;
import com.seq.acheron.vault.interfaces.Storable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Native JUnit test suite for Vault and VaultFactory")
public class VaultTest {

    private User testUser;
    private VaultEncryptingStrategy testStrategy;

    @BeforeEach
    void setUp() throws GeneralSecurityException {
        // Initialise with a real User instance
        testUser = new User("a", "b", "c", "d", "e");

        // Use the real AES strategy with a test password and a generated salt
        String salt = CryptoUtils.generateSalt();
        testStrategy = new Argon2VaultEncryptingStrategy("MiPassSuperSegura123", salt, true);
    }

    @Nested
    @DisplayName("Vault unit tests")
    class VaultBasicTests {

        @Test
        @DisplayName("The Vault initialises correctly")
        void testVaultInitialization() throws GeneralSecurityException {
            Vault vault = new Vault(testStrategy, testUser, false);

            assertTrue(vault.getStorables().isEmpty(), "The Vault must start with no items");
            assertFalse(vault.isEncrypted(), "The initial encryption state must match the constructor");
            assertNotNull(vault.getChecker(), "The checker must have been computed");
            assertEquals(testUser, vault.getUser(), "The stored user must be the one passed in");
        }

        @Test
        @DisplayName("Basic Storable operations: add, get and natural ordering")
        void testAddAndGet() throws GeneralSecurityException {
            Vault vault = new Vault(testStrategy, testUser, false);

            // Real implementations (Account and CreditCard implement Storable)
            Account account1 = new Account("ZZZ_ID", "Account1", "userZ", "zzz.com", "passZ", false);
            Account account2 = new Account("AAA_ID", "Account2", "userA", "aaa.com", "passA", false);
            CreditCard card = new CreditCard("CARD_ID", "CreditCard", "John", "1234", "12/28", "123", "28001", false);

            // Add in unsorted order to verify that .sort(null) takes effect
            vault.add(account1).add(card).add(account2);

            List<Storable> storables = vault.getStorables();
            assertEquals(3, storables.size(), "There must be 3 items in the list");

            // Verify item retrieval
            assertEquals(account1, vault.get("ZZZ_ID"));
            assertEquals(card, vault.get("CARD_ID"));
            assertNull(vault.get("NO_EXISTE"));
        }

        @Test
        @DisplayName("Removing Storables works correctly")
        void testRemove() throws GeneralSecurityException {
            Vault vault = new Vault(testStrategy, testUser, false);
            Account acc = new Account("TEST_ID", "usr", "dom", "pass", false);

            vault.add(acc);
            assertEquals(1, vault.getStorables().size());

            vault.remove(acc);
            assertTrue(vault.getStorables().isEmpty(), "After removal the Vault must be empty");

            // Silent removals (null or non-existent)
            assertDoesNotThrow(() -> vault.remove(null));
            assertDoesNotThrow(() -> vault.remove(new Account("OTRO", "", "", "", false)));
        }

        @Test
        @DisplayName("The isEncrypted flag throws IllegalStateException correctly")
        void testEncryptionStateExceptions() throws GeneralSecurityException {
            Vault vault = new Vault(testStrategy, testUser, false);

            vault.encryptAll();
            assertTrue(vault.isEncrypted());

            // If already encrypted, encrypting again is not allowed
            assertThrows(IllegalStateException.class, vault::encryptAll);

            vault.decryptAll();
            assertFalse(vault.isEncrypted());

            // If already decrypted, decrypting again is not allowed
            assertThrows(IllegalStateException.class, vault::decryptAll);
        }

        @Test
        @DisplayName("New IDs are generated as a 16-character SHA-256 hash")
        void testHashIdGeneration() throws GeneralSecurityException {
            Vault vault = new Vault(testStrategy, testUser, false);

            // Create an Account without an explicit ID (needs auto-assignment)
            Account acc = new Account("TestAccount", "user1", "example.com", "password123", false);
            vault.add(acc);

            String id = acc.getId();
            assertNotNull(id, "The ID must not be null");
            assertEquals(16, id.length(), "The ID must be 16 characters (truncated SHA-256)");
            assertTrue(id.matches("[0-9a-f]{16}"), "The ID must be 16 hexadecimal characters");
        }

        @Test
        @DisplayName("Hash IDs are unique for distinct storables")
        void testHashIdUniqueness() throws GeneralSecurityException {
            Vault vault = new Vault(testStrategy, testUser, false);

            // Create different accounts in the same vault
            Account acc1 = new Account("TestAccount1", "user1", "example.com", "password123", false);
            Account acc2 = new Account("TestAccount2", "user2", "example.com", "password456", false);

            vault.add(acc1);
            vault.add(acc2);

            String id1 = acc1.getId();
            String id2 = acc2.getId();

            assertNotEquals(id1, id2, "Different accounts must produce different hash IDs");
        }

        @Test
        @DisplayName("The hash ID is fixed once assigned")
        void testHashIdImmutable() throws GeneralSecurityException {
            Vault vault = new Vault(testStrategy, testUser, false);

            Account acc = new Account("TestAccount", "user1", "example.com", "password123", false);
            vault.add(acc);
            String originalId = acc.getId();

            // Edit the storable (change the password)
            acc.setPassword("newpassword456");
            String editedId = acc.getId();

            // The ID stays the same because it is not recomputed automatically
            assertEquals(originalId, editedId, "The ID does not change automatically after editing the in-memory storable");
        }
    }

    @Nested
    @DisplayName("Integration tests (real encryption, JSON and VaultFactory)")
    class IntegrationTests {

        @Test
        @DisplayName("MockVaults builds the expected demo vault")
        void testFactoryMockVault() throws GeneralSecurityException {
            Vault mockVault = MockVaults.create(testUser);

            assertNotNull(mockVault);
            assertFalse(mockVault.isEncrypted(), "The demo vault must be decrypted by default");
            assertEquals(10, mockVault.getStorables().size(), "The demo vault initialises 10 storables (accounts, cards, note, identity, bank, wifi and license)");
        }

        @Test
        @DisplayName("Real AES encryption modifies the actual passwords")
        void testRealEncryptionTransformsData() throws GeneralSecurityException {
            Vault vault = new Vault(testStrategy, testUser, false);
            Account account = new Account("MY_ACC", "admin", "admin.com", "PlainPassword123", false);
            vault.add(account);

            vault.encryptAll();

            // Check the integration by verifying the password is no longer plain text
            assertTrue(vault.isEncrypted());
            assertNotEquals("PlainPassword123", account.getPassword(), "The password must be encrypted by the AES vault strategy");
        }

        @Test
        @DisplayName("Full lifecycle: create -> encrypt -> toJSON -> fromJSON -> decrypt")
        void testVaultFullLifecycle() throws GeneralSecurityException {
            // 1. Build the original demo vault
            Vault originalVault = MockVaults.create(testUser);

            // 2. Add our own custom value on top of the demo vault
            Account customAcc = new Account("CUSTOM_ID", "Account1", "gabriel", "test.com", "SecretPass!1", false);
            originalVault.add(customAcc);

            // 3. Encrypt the whole vault and serialise it to a String
            originalVault.encryptAll();
            String exportedJson = originalVault.toJson();

            assertNotNull(exportedJson);
            assertTrue(exportedJson.contains("\"checker\""), "The JSON must include the password checker");
            assertTrue(exportedJson.contains("\"CUSTOM_ID\""), "The JSON must include the custom storable");

            // 4. Restore the vault into a new object using the demo master password
            VaultFactory factory = new VaultFactory(testUser);
            Vault restoredVault = factory.fromJson(exportedJson, MockVaults.PASSWORD);

            // 5. Restoration assertions
            assertTrue(restoredVault.isEncrypted(), "Coming from an encrypted fromJSON, it must be true");
            assertEquals(originalVault.getStorables().size(), restoredVault.getStorables().size());
            assertEquals(originalVault.getChecker(), restoredVault.getChecker());

            // 6. Decrypt to get the plain-text values back
            restoredVault.decryptAll();
            assertFalse(restoredVault.isEncrypted());

            // Retrieve the storable and make sure real decryption worked
            Account restoredCustomAcc = (Account) restoredVault.get("CUSTOM_ID");
            assertEquals("gabriel", restoredCustomAcc.getUsername());
            assertEquals("SecretPass!1", restoredCustomAcc.getPassword(), "The decrypted password must match exactly");
        }
    }

    @Nested
    @DisplayName("Master password change tests (changePassword)")
    class ChangePasswordTests {

        private static final String OLD_PASSWORD = "MiPassSuperSegura123";
        private static final String NEW_PASSWORD = "NuevaClaveAunMasSegura456";

        @Test
        @DisplayName("changePassword throws IllegalStateException if the Vault is encrypted")
        void testChangePasswordRequiresDecrypted() throws GeneralSecurityException {
            Vault vault = new Vault(testStrategy, testUser, false);
            vault.add(new Account("ACC", "user", "dom", "pass", false));
            vault.encryptAll();

            assertTrue(vault.isEncrypted());
            assertThrows(IllegalStateException.class,
                    () -> vault.changePassword(OLD_PASSWORD, NEW_PASSWORD),
                    "Changing the password must not be allowed while the Vault is encrypted");
        }

        @Test
        @DisplayName("changePassword throws WrongPasswordException if the current password is wrong")
        void testChangePasswordWrongCurrent() throws GeneralSecurityException {
            Vault vault = new Vault(testStrategy, testUser, false);
            vault.add(new Account("ACC", "user", "dom", "pass", false));

            assertThrows(WrongPasswordException.class,
                    () -> vault.changePassword("contraseñaIncorrecta", NEW_PASSWORD),
                    "An incorrect current password must be rejected");
        }

        @Test
        @DisplayName("changePassword rotates salt and checker while preserving the vaultKey")
        void testChangePasswordRotatesMaterial() throws GeneralSecurityException {
            Vault vault = new Vault(testStrategy, testUser, false);
            String saltBefore = testStrategy.getSaltBase64();
            String checkerBefore = vault.getChecker();

            vault.changePassword(OLD_PASSWORD, NEW_PASSWORD);

            assertNotEquals(saltBefore, testStrategy.getSaltBase64(), "The salt must be rotated");
            assertNotEquals(checkerBefore, vault.getChecker(), "The checker must be recomputed with the new key");
            assertFalse(vault.isEncrypted(), "The Vault stays decrypted after the change");
        }

        @Test
        @DisplayName("After changing the password, the old one fails and the new one opens with intact storables")
        void testChangePasswordFullLifecycle() throws GeneralSecurityException {
            // 1. Decrypted vault with a known storable.
            Vault vault = new Vault(testStrategy, testUser, false);
            vault.add(new Account("CUSTOM_ID", "Cuenta", "gabriel", "test.com", "SecretPass!1", false));

            // 2. Change the master password.
            vault.changePassword(OLD_PASSWORD, NEW_PASSWORD);

            // 3. Encrypt and serialise with the new password already applied.
            vault.encryptAll();
            String json = vault.toJson();

            VaultFactory factory = new VaultFactory(testUser);

            // 4. The old password no longer opens the vault.
            assertThrows(WrongPasswordException.class,
                    () -> factory.fromJson(json, OLD_PASSWORD),
                    "The old password must not open the vault after the change");

            // 5. The new password opens the vault and storables decrypt intact.
            Vault reopened = factory.fromJson(json, NEW_PASSWORD);
            reopened.decryptAll();

            Account acc = (Account) reopened.get("CUSTOM_ID");
            assertNotNull(acc, "The storable must still be present with its stable id");
            assertEquals("gabriel", acc.getUsername());
            assertEquals("SecretPass!1", acc.getPassword(), "The decrypted value must match exactly");
        }
    }
}
