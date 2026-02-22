package com.seq.acheron.vault.interfaces;

import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.storables.Account;
import com.seq.acheron.vault.storables.CreditCard;
import com.seq.acheron.vault.storables.VaultObject;

/**
 * Represents a vault entry whose sensitive fields can be encrypted and
 * decrypted using a {@link VaultEncryptingStrategy}.
 * <p>
 * Each implementation decides which fields are considered sensitive and how
 * they are transformed (for example, storing an encrypted password as a
 * Base64-encoded {@code IV || ciphertext} string).
 * <p>
 * Known implementations:
 * <ul>
 *   <li>{@link Account} — stores username, domain, and password.</li>
 *   <li>{@link CreditCard} — stores card number, CVV, and expiration date.</li>
 * </ul>
 *
 * @see VaultObject
 * @see VaultEncryptingStrategy
 */
public interface Storable {

    /**
     * Returns the unique identifier for this vault entry.
     * <p>
     * The ID is composed of a type-specific prefix followed by a sequential
     * number (e.g. {@code "ACC0"} for the first account, {@code "CDC1"} for
     * the second credit card). Supported prefixes are:
     * <ul>
     *   <li>{@code ACC} — account</li>
     *   <li>{@code CDC} — credit/debit card</li>
     * </ul>
     *
     * @return the unique ID of this entry; never {@code null}
     */
    String getId();

    /**
     * Encrypts all sensitive fields of this entry using the provided strategy.
     * <p>
     * After this call, the encrypted fields will hold Base64-encoded
     * {@code IV || ciphertext} values. The entry's internal {@code isEncrypted}
     * flag is set to {@code true}.
     *
     * @param encryptingStrategy the encryption strategy to use; must not be
     *                           {@code null}
     * @return a human-readable snapshot of the object's state
     *         <b>before</b> encryption (e.g. its {@code toString()} value)
     * @throws IllegalStateException if the entry is already encrypted
     */
    String encrypt(VaultEncryptingStrategy encryptingStrategy);

    /**
     * Decrypts all sensitive fields of this entry using the provided strategy.
     * <p>
     * The strategy used here must be compatible with the one used during
     * {@link #encrypt}. After this call, the fields will hold plain-text values
     * and the internal {@code isEncrypted} flag is set to {@code false}.
     *
     * @param encryptingStrategy the decryption strategy to use; must match
     *                           the one used for encryption
     * @return a snapshot of the object's encrypted state
     *         <b>before</b> decryption
     * @throws IllegalStateException if the entry is not encrypted
     */
    String decrypt(VaultEncryptingStrategy encryptingStrategy);

    /**
     * Returns whether this entry's sensitive fields are currently encrypted.
     *
     * @return {@code true} if the fields hold cipher-text; {@code false} if
     *         they hold plain-text
     */
    boolean isEncrypted();

    /**
     * Returns a JSON representation of this entry.
     * <p>
     * Implementations must ensure that highly sensitive values (e.g. full card
     * numbers, CVV codes) are masked when the entry is in plain-text state.
     *
     * @return a JSON string representing this entry's current state
     */
    String toJson();

    Storable copy();

    default String category() {
        return getClass().getSimpleName().toLowerCase() + "s";
    }
}
