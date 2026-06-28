package com.seq.acheron.vault.interfaces;

import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;

/**
 * Represents a vault entry whose sensitive fields can be encrypted and
 * decrypted using a {@link VaultEncryptingStrategy}.
 * <p>
 * Each implementation decides which fields are considered sensitive and how
 * they are transformed (for example, storing an encrypted password as a
 * Base64-encoded {@code IV || ciphertext} string).
 *
 * @see VaultEncryptingStrategy
 */
public interface Storable extends Cypher {

    /**
     * Returns the unique identifier for this vault entry.
     * <p>
     * Newly created entries receive a deterministic 16-character hexadecimal ID
     * derived from a SHA-256 hash of their encrypted content (see
     * {@code VaultObject.generateIdFromContent}). Entries loaded from storage
     * keep the ID they were persisted with.
     *
     * @return the unique ID of this entry; never {@code null} once stored
     */
    String getId();

    /**
     * Returns a JSON representation of this entry. This single representation
     * intentionally serves two purposes, both "safe to expose as-is":
     * <ul>
     *   <li>While encrypted, it is the persistence/transport format — every
     *       field is cipher-text, so it is safe to store or transmit verbatim
     *       (this is what {@link com.seq.acheron.vault.Vault#toJson()} relies on).</li>
     *   <li>While in plain-text state, it is a display-safe snapshot — implementations
     *       must mask highly sensitive values (e.g. full card numbers, CVV codes)
     *       instead of revealing them.</li>
     * </ul>
     * Implementations typically delegate the per-field choice to a helper such as
     * {@code VaultObject.revealOrMask(String, String)} to make this explicit.
     *
     * @return a JSON string representing this entry's current state
     */
    String toJson();

    Storable copy();

    /**
     * Returns the persistence category (JSON array key) this entry is grouped
     * under, e.g. {@code "accounts"} or {@code "creditcards"}.
     * <p>
     * Implementations must return an explicit, stable value: it is part of the
     * persisted format and must not be derived from the class name, so renaming
     * a class never changes the stored layout.
     *
     * @return the category key; never {@code null}
     */
    String category();
}
