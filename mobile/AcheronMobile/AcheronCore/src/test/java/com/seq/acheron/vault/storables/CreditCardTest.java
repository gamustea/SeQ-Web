package com.seq.acheron.vault.storables;

import com.seq.acheron.vault.User;
import com.seq.acheron.vault.Vault;
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import static com.seq.acheron.util.CryptoUtils.generateSalt;
import static org.junit.jupiter.api.Assertions.*;

public class CreditCardTest {

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

    private CreditCard card;

    @BeforeEach
    void setUp() {
        card = new CreditCard("CDC0", "A Card", "Juan P\u00e9rez", "1234567812345678", "12/29", "123", "28001", false);
    }

    @Test
    void encryptThenDecrypt_restoresOriginalFields() throws Exception {
        CreditCard card = new CreditCard(
                "CDC0", "A Card",
                "John Doe",
                "4111111111111111",
                "12/29",
                "123",
                "28001",
                false
        );

        TestVaultStrategy strategy = new TestVaultStrategy();

        String beforeEncrypt = card.toString();
        String returnedFromEncrypt = card.encrypt(strategy);

        assertEquals(beforeEncrypt, returnedFromEncrypt,
                "encrypt should return the string representation of the previous state");

        assertNotEquals("John Doe", card.getCardHolderName());
        assertNotEquals("4111111111111111", card.getCardNumber());
        assertNotEquals("12/29", card.getExpirationDate());
        assertNotEquals("123", card.getCvv());
        assertNotEquals("28001", card.getPostalCode());

        String beforeDecrypt = card.toString();
        String returnedFromDecrypt = card.decrypt(strategy);

        assertEquals(beforeDecrypt, returnedFromDecrypt,
                "decrypt should return the string representation of the previous (encrypted) state");

        assertEquals("John Doe", card.getCardHolderName());
        assertEquals("4111111111111111", card.getCardNumber());
        assertEquals("12/29", card.getExpirationDate());
        assertEquals("123", card.getCvv());
        assertEquals("28001", card.getPostalCode());

        System.out.println("[OK] CreditCard.encryptThenDecrypt_restoresOriginalFields");
    }

    @Test
    void idsHaveCdcPrefixAndIncrementPerInstance() throws Exception {
        Vault vault = new Vault(new TestVaultStrategy(), new User("u1", "a", "b", "c", "d"), false);

        CreditCard c1 = new CreditCard("Card1", "N1", "4111111111111111", "01/30", "111", "28001", false);
        CreditCard c2 = new CreditCard("Card2", "N2", "4222222222222222", "02/31", "222", "28002", false);
        vault.add(c1).add(c2);

        String id1 = c1.getId();
        String id2 = c2.getId();

        // IDs nuevos son hash de 16 caracteres hexadecimales
        assertEquals(16, id1.length(), "Card ID should be 16 hex characters");
        assertEquals(16, id2.length(), "Card ID should be 16 hex characters");
        assertTrue(id1.matches("[0-9a-f]{16}"), "Card ID should be hexadecimal");
        assertTrue(id2.matches("[0-9a-f]{16}"), "Card ID should be hexadecimal");

        assertNotEquals(id1, id2, "IDs must be unique");

        System.out.printf("[OK] CreditCard.idsHaveCdcPrefixAndIncrementPerInstance: %s, %s%n", id1, id2);
    }

    @Test
    void isEncryptedFlag_startsAsFalse_whenConstructedWithPlainText() {
        CreditCard card = new CreditCard("CDC0", "A Card", "Holder", "4111111111111111", "12/29", "123", "28001", false);

        assertFalse(card.isEncrypted(), "CreditCard should not be encrypted initially");

        System.out.println("[OK] CreditCard.isEncryptedFlag_startsAsFalse_whenConstructedWithPlainText");
    }

    @Test
    void isEncryptedFlag_startsAsTrue_whenConstructedWithEncryptedData() {
        CreditCard card = new CreditCard("CDC0", "A Card",
                "EncryptedHolder",
                "EncryptedNumber",
                "EncryptedDate",
                "EncryptedCVV",
                "EncryptedPostal",
                true
        );

        assertTrue(card.isEncrypted(), "CreditCard should be marked as encrypted");

        System.out.println("[OK] CreditCard.isEncryptedFlag_startsAsTrue_whenConstructedWithEncryptedData");
    }

    @Test
    void isEncryptedFlag_becomesTrue_afterEncryption() throws Exception {
        CreditCard card = new CreditCard("CDC0", "A Card", "Holder", "4111111111111111", "12/29", "123", "28001", false);
        TestVaultStrategy strategy = new TestVaultStrategy();

        assertFalse(card.isEncrypted(), "CreditCard should start unencrypted");

        card.encrypt(strategy);

        assertTrue(card.isEncrypted(), "CreditCard should be encrypted after encrypt()");

        System.out.println("[OK] CreditCard.isEncryptedFlag_becomesTrue_afterEncryption");
    }

    @Test
    void isEncryptedFlag_becomesFalse_afterDecryption() throws Exception {
        CreditCard card = new CreditCard("CDC0", "A Card", "Holder", "4111111111111111", "12/29", "123", "28001", false);
        TestVaultStrategy strategy = new TestVaultStrategy();

        card.encrypt(strategy);
        assertTrue(card.isEncrypted(), "CreditCard should be encrypted");

        card.decrypt(strategy);

        assertFalse(card.isEncrypted(), "CreditCard should be decrypted after decrypt()");

        System.out.println("[OK] CreditCard.isEncryptedFlag_becomesFalse_afterDecryption");
    }

    @Test
    void encryptTwice_throwsIllegalStateException() throws Exception {
        CreditCard card = new CreditCard("CDC0", "A Card", "Holder", "4111111111111111", "12/29", "123", "28001", false);
        TestVaultStrategy strategy = new TestVaultStrategy();

        card.encrypt(strategy);

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            card.encrypt(strategy);
        });

        assertTrue(exception.getMessage().contains("already encrypted"),
                "Exception message should mention object is already encrypted");

        System.out.println("[OK] CreditCard.encryptTwice_throwsIllegalStateException");
    }

    @Test
    void decryptUnencryptedObject_throwsIllegalStateException() throws Exception {
        CreditCard card = new CreditCard("CDC0", "A Card", "Holder", "4111111111111111", "12/29", "123", "28001", false);
        TestVaultStrategy strategy = new TestVaultStrategy();

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            card.decrypt(strategy);
        });

        assertTrue(exception.getMessage().contains("not encrypted"),
                "Exception message should mention object is not encrypted");

        System.out.println("[OK] CreditCard.decryptUnencryptedObject_throwsIllegalStateException");
    }

    @Test
    void copy_preservesIsEncryptedFlag() throws Exception {
        CreditCard original = new CreditCard("CDC0", "A Card", "Holder", "4111111111111111", "12/29", "123", "28001", false);
        TestVaultStrategy strategy = new TestVaultStrategy();

        original.encrypt(strategy);
        assertTrue(original.isEncrypted());

        CreditCard copy = (CreditCard) original.copy();

        assertTrue(copy.isEncrypted(), "Copy should preserve isEncrypted flag");
        assertEquals(original.getCardHolderName(), copy.getCardHolderName());
        assertEquals(original.getCardNumber(), copy.getCardNumber());
        assertEquals(original.getExpirationDate(), copy.getExpirationDate());
        assertEquals(original.getCvv(), copy.getCvv());
        assertEquals(original.getPostalCode(), copy.getPostalCode());

        System.out.println("[OK] CreditCard.copy_preservesIsEncryptedFlag");
    }

    @Test
    void testtoJson_SensitiveMasking() {
        String json = card.toJson();
        assertTrue(json.contains("id"));
        assertTrue(json.contains("createdAt"));
        assertTrue(json.contains("cardHolderName"));
        assertTrue(json.contains("****5678"));
        assertTrue(json.contains("12/29"));
    }
}
