package com.seq.acheron.vault;

import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.storables.Storable;
import lombok.Getter;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * A secure container that stores and manages {@link Storable} objects,
 * optionally encrypting or decrypting all of them as a single unit using a
 * shared {@link VaultEncryptingStrategy}.
 * <p>
 * A {@code Vault} maintains:
 * <ul>
 *   <li>A mutable list of {@link Storable} items (accounts, credit cards, etc.).</li>
 *   <li>A fixed {@link VaultEncryptingStrategy} determining the cipher and key
 *       derivation algorithm used to protect stored data.</li>
 *   <li>An {@link #isEncrypted} flag reflecting whether the items currently
 *       hold cipher-text ({@code true}) or plain-text ({@code false}).</li>
 * </ul>
 * <p>
 * Typical usage:
 * <pre>{@code
 * Vault vault = new Vault(strategy);
 * vault.add(new Account("alice", "github.com", "s3cr3t", false));
 * vault.encryptAll();   // all items are now encrypted
 * // ... persist the vault ...
 * vault.decryptAll();   // all items restored to plain-text
 * }</pre>
 *
 * @see Storable
 * @see VaultEncryptingStrategy
 */
@Getter
public class Vault {

    /**
     * The encryption strategy shared by all items in this vault.
     */
    private final VaultEncryptingStrategy strategy;

    /**
     * The ordered list of items stored in this vault.
     */
    private final List<Storable> storables = new ArrayList<>();

    /**
     * {@code true} if all items currently hold encrypted (cipher-text) values;
     * {@code false} if they hold plain-text values.
     * Updated automatically by {@link #encryptAll()} and {@link #decryptAll()}.
     */
    private boolean isEncrypted;

    /**
     * Creates a new, empty vault with the given encryption strategy.
     *
     * @param strategy the strategy used for all encrypt/decrypt operations;
     *                 must not be {@code null}
     * @throws NoSuchAlgorithmException if the strategy cannot be initialised
     *                                  due to an unsupported algorithm
     */
    public Vault(VaultEncryptingStrategy strategy) throws NoSuchAlgorithmException {
        this.strategy = strategy;
    }

    /**
     * Retrieves a stored item by its unique identifier.
     *
     * @param id the item's ID (e.g. {@code "ACC0"}, {@code "CDC1"})
     * @return the matching {@link Storable}, or {@code null} if none is found
     */
    public Storable get(String id) {
        return storables.stream()
                .filter(s -> s.getId().equals(id))
                .findFirst()
                .orElse(null);
    }

    /**
     * Adds an item to the vault.
     * <p>
     * No duplicate check is performed. Callers are responsible for ensuring
     * that IDs remain unique if that is a requirement.
     *
     * @param storable the item to add; must not be {@code null}
     */
    public void add(Storable storable) {
        storables.add(storable);
    }

    /**
     * Removes an item from the vault using {@link Object#equals} for comparison.
     * If the item is not present, this method has no effect.
     *
     * @param storable the item to remove
     */
    public void remove(Storable storable) {
        storables.remove(storable);
    }

    /**
     * Encrypts all items currently stored in the vault by delegating to
     * {@link Storable#encrypt(VaultEncryptingStrategy)} for each item.
     * Sets {@link #isEncrypted} to {@code true} on success.
     *
     * @throws IllegalStateException if the vault is already encrypted
     */
    public void encryptAll() {
        toggleEncrypt(true);
    }

    /**
     * Decrypts all items currently stored in the vault by delegating to
     * {@link Storable#decrypt(VaultEncryptingStrategy)} for each item.
     * Sets {@link #isEncrypted} to {@code false} on success.
     *
     * @throws IllegalStateException if the vault is not currently encrypted
     */
    public void decryptAll() {
        toggleEncrypt(false);
    }

    /**
     * Internal helper that applies the encrypt or decrypt operation to every
     * stored item and updates {@link #isEncrypted}.
     *
     * @param encrypt {@code true} to encrypt all items; {@code false} to decrypt
     * @throws IllegalStateException if the operation conflicts with the current
     *                               {@link #isEncrypted} state
     */
    private void toggleEncrypt(boolean encrypt) {
        if (encrypt && isEncrypted) {
            throw new IllegalStateException("Vault is already encrypted.");
        }
        if (!encrypt && !isEncrypted) {
            throw new IllegalStateException("Vault is already decrypted.");
        }

        for (Storable storable : storables) {
            if (encrypt) {
                storable.encrypt(strategy);
            } else {
                storable.decrypt(strategy);
            }
        }
        isEncrypted = encrypt;
    }
}
