package com.seq.acheron.vault;

import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.interfaces.JsonSerializable;
import com.seq.acheron.vault.interfaces.Storable;
import com.seq.acheron.vault.storables.VaultObject;
import lombok.Getter;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * A secure container that stores and manages {@link Storable} objects,
 * optionally encrypting or decrypting all of them as a single unit using a
 * shared {@link VaultEncryptingStrategy}.
 * <p>
 * A {@code Vault} maintains:
 * <ul>
 *   <li>A mutable, ordered list of {@link Storable} items (accounts, credit cards, etc.).</li>
 *   <li>A fixed {@link VaultEncryptingStrategy} determining the cipher and key
 *       derivation algorithm used to protect stored data.</li>
 *   <li>An {@link #isEncrypted} flag reflecting whether the items currently
 *       hold cipher-text ({@code true}) or plain-text ({@code false}).</li>
 *   <li>A {@link #checker} value used to validate the master password when
 *       reloading a persisted vault.</li>
 * </ul>
 * <p>
 * Typical usage:
 * <pre>{@code
 * Vault vault = new Vault(strategy, user, false);
 * vault.add(new Account("alice", "github.com", "s3cr3t", false));
 * vault.encryptAll();   // all items are now encrypted
 * // ... persist the vault ...
 * vault.decryptAll();   // all items restored to plain-text
 * }</pre>
 *
 * <p>
 * This class is intentionally small and focused: it does not know how to
 * persist itself, it only knows how to:
 * <ul>
 *     <li>Keep track of items and their encryption state.</li>
 *     <li>Encrypt/decrypt all items using the configured strategy.</li>
 *     <li>Export a JSON representation suitable for persistence.</li>
 * </ul>
 *
 * @see Storable
 * @see VaultEncryptingStrategy
 */
@Getter
public class Vault implements JsonSerializable {

    /* ═══════════════════════════════════════
     *                FIELDS
     * ═══════════════════════════════════════ */

    /**
     * The encryption strategy shared by all items in this vault.
     * <p>
     * It encapsulates the cipher, key derivation and key management details
     * required to protect the data stored in this vault.
     */
    private final VaultEncryptingStrategy strategy;

    /**
     * The ordered list of items stored in this vault.
     * <p>
     * Items are kept sorted according to their natural ordering (see
     * {@link java.lang.Comparable}) every time a new element is added.
     */
    private final List<Storable> storables = new ArrayList<>();

    /**
     * {@code true} if all items currently hold encrypted (cipher-text) values;
     * {@code false} if they hold plain-text values.
     * <p>
     * This flag is updated automatically by {@link #encryptAll()} and
     * {@link #decryptAll()} to reflect the state of the underlying data.
     */
    private boolean isEncrypted;

    /**
     * Encrypted verifier derived from the user's username and the master password.
     * <p>
     * Computed as:
     * <pre>
     *   encryptWithDerivedKey( SHA-256( username ) )
     * </pre>
     * using the current {@link VaultEncryptingStrategy}. This value is later
     * used by {@link com.seq.acheron.vault.VaultFactory} to validate that the
     * master password supplied when loading a vault is correct, without ever
     * storing the password itself.
     */
    private final String checker;

    /**
     * The logical owner of this vault. It is used when deriving the
     * {@link #checker} value and for higher-level business logic.
     */
    private final User user;



    /* ═══════════════════════════════════════
     *             CONSTRUCTORS
     * ═══════════════════════════════════════ */

    /**
     * Creates a new, empty vault with the given encryption strategy.
     *
     * @param strategy    the strategy used for all encrypt/decrypt operations;
     *                    must not be {@code null}
     * @param user        the owner of this vault; must not be {@code null}
     * @param isEncrypted initial encryption state of the contained items
     * @throws GeneralSecurityException if the {@link MessageDigest} algorithm
     *                                  required to compute the checker cannot
     *                                  be initialised
     */
    public Vault(VaultEncryptingStrategy strategy, User user, boolean isEncrypted)
            throws GeneralSecurityException {

        this.strategy = Objects.requireNonNull(strategy, "strategy must not be null");
        this.user = Objects.requireNonNull(user, "user must not be null");
        this.isEncrypted = isEncrypted;
        this.checker = strategy.getChecker(user.getUsername());
    }

    /**
     * Creates a vault instance from already persisted cryptographic material.
     * <p>
     * This constructor is typically used when re-hydrating a vault from disk,
     * where the {@link #checker} is already stored alongside the vault content.
     *
     * @param strategy    encryption strategy associated with this vault
     * @param user        vault owner
     * @param checker     previously computed checker value
     * @param isEncrypted current encryption state of the items
     */
    public Vault(VaultEncryptingStrategy strategy,
                 User user,
                 String checker,
                 boolean isEncrypted) throws GeneralSecurityException {

        this.strategy = Objects.requireNonNull(strategy, "strategy must not be null");
        this.user = Objects.requireNonNull(user, "user must not be null");
        this.checker = Objects.requireNonNull(checker, "checker must not be null");
        this.isEncrypted = isEncrypted;
    }



    /* ═══════════════════════════════════════
     *               METHODS
     * ═══════════════════════════════════════ */

    /**
     * Retrieves a stored item by its unique identifier.
     *
     * @param id the item's ID (e.g. {@code "ACC0"}, {@code "CDC1"})
     * @return the matching {@link Storable}, or {@code null} if none is found
     */
    public Storable get(String id) {
        Objects.requireNonNull(id, "id must not be null");
        return storables.stream()
                .filter(s -> id.equals(s.getId()))
                .findFirst()
                .orElse(null);
    }

    /**
     * Adds an item to the vault.
     * <p>
     * No duplicate check is performed. Callers are responsible for ensuring
     * that IDs remain unique if that is a requirement for their use-case.
     * After insertion, the internal list of items is re-sorted according to
     * the natural ordering of {@link Storable}.
     *
     * @param storable the item to add; must not be {@code null}
     * @return this vault instance, for fluent usage
     */
    public Vault add(Storable storable) {
        Objects.requireNonNull(storable, "storable must not be null");
        storables.add(storable);
        storables.sort(null);
        return this;
    }

    /**
     * Removes an item from the vault using {@link Object#equals(Object)} for comparison.
     * If the item is not present, this method has no effect.
     *
     * @param storable the item to remove; ignored if {@code null} or not contained
     * @return this vault instance, for fluent usage
     */
    public Vault remove(Storable storable) {
        if (storable != null) {
            storables.remove(storable);
        }
        return this;
    }

    /**
     * Encrypts all items currently stored in the vault by delegating to
     * {@link Storable#encrypt(VaultEncryptingStrategy)} for each item.
     * Sets {@link #isEncrypted} to {@code true} on success.
     *
     * @return this vault instance, for fluent usage
     * @throws IllegalStateException if the vault is already encrypted
     */
    public Vault encryptAll() {
        return toggleEncrypt(true);
    }

    /**
     * Decrypts all items currently stored in the vault by delegating to
     * {@link Storable#decrypt(VaultEncryptingStrategy)} for each item.
     * Sets {@link #isEncrypted} to {@code false} on success.
     *
     * @return this vault instance, for fluent usage
     * @throws IllegalStateException if the vault is not currently encrypted
     */
    public Vault decryptAll() {
        return toggleEncrypt(false);
    }

    /**
     * Internal helper that applies the encrypt or decrypt operation to every
     * stored item and updates {@link #isEncrypted}.
     *
     * @param encrypt {@code true} to encrypt all items; {@code false} to decrypt
     * @return this vault instance
     * @throws IllegalStateException if the operation conflicts with the current
     *                               {@link #isEncrypted} state
     */
    private Vault toggleEncrypt(boolean encrypt) {
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
        return this;
    }

    /**
     * Classifies all stored items by their {@link Storable#category()}.
     * <p>
     * The returned map uses a {@link TreeMap} to ensure stable, alphabetical
     * ordering of categories in the JSON representation.
     */
    private Map<String, List<Storable>> classifyStorables() {
        Map<String, List<Storable>> map = new TreeMap<>();
        for (Storable storable : storables) {
            String key = storable.category();
            map.computeIfAbsent(key, k -> new ArrayList<>())
                    .add(storable);
        }
        return map;
    }

    /**
     * Serialises this vault to a JSON string suitable for persistence.
     * <p>
     * The JSON includes:
     * <ul>
     *   <li>{@code checker}: the encrypted verifier bound to the master password.</li>
     *   <li>{@code vaultKey}: the exported key material from
     *       {@link VaultEncryptingStrategy#exportVaultKey()}.</li>
     *   <li>One array per {@link Storable#category()}, containing the JSON form
     *       of each stored item.</li>
     * </ul>
     *
     * @return JSON representation of this vault
     * @throws GeneralSecurityException if exporting the vault key fails
     */
    public String toJson() throws GeneralSecurityException {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"checker\": \"").append(checker).append("\", ");
        sb.append("\"vaultKey\": \"").append(strategy.exportVaultKey()).append("\", ");
        // strategy.toJson() returns a JSON *object* (not a quoted string),
        // so it is embedded directly without extra quotes.
        sb.append("\"algorithm\": ").append(strategy.toJson()).append(", ");

        Map<String, List<Storable>> map = classifyStorables();
        boolean firstEntry = true;

        for (Map.Entry<String, List<Storable>> entry : map.entrySet()) {
            if (!firstEntry) {
                sb.append(", ");
            }
            firstEntry = false;

            sb.append("\"").append(entry.getKey()).append("\": [");
            List<Storable> group = entry.getValue();
            for (int i = 0; i < group.size(); i++) {
                sb.append(group.get(i).toJson());
                if (i < group.size() - 1) {
                    sb.append(", ");
                }
            }
            sb.append("]");
        }

        sb.append("}");
        return sb.toString();
    }

    public VaultObject fromJson(String json) throws GeneralSecurityException {
        return null;
    }


    /**
     * Delegates to {@link #toJson()} and wraps any {@link GeneralSecurityException}
     * into a {@link RuntimeException}.
     */
    @Override
    public String toString() {
        try {
            return toJson();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to serialise vault to JSON", e);
        }
    }

    /**
     * Two vaults are considered equal if they share the same:
     * <ul>
     *   <li>encryption strategy,</li>
     *   <li>owner ({@link User}),</li>
     *   <li>{@link #checker} value,</li>
     *   <li>encryption state ({@link #isEncrypted}),</li>
     *   <li>and list of {@link Storable} items (including order).</li>
     * </ul>
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Vault that)) return false;
        return isEncrypted == that.isEncrypted
                && Objects.equals(strategy, that.strategy)
                && Objects.equals(user, that.user)
                && Objects.equals(checker, that.checker)
                && Objects.equals(storables, that.storables);
    }

    @Override
    public int hashCode() {
        return Objects.hash(strategy, user, checker, storables, isEncrypted);
    }
}
