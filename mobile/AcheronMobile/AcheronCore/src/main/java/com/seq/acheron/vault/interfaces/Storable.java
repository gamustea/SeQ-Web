package com.seq.acheron.vault.interfaces;

import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
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
public interface Storable extends Cypher {

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
