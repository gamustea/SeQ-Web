package com.seq.acheron.vault;

import com.seq.acheron.agents.User;
import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.storables.Storable;
import lombok.Getter;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

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

    /* ═══════════════════════════════════════
     *                FIELDS
     * ═══════════════════════════════════════ */

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

    private final String checker;

    private final User user;



    /* ═══════════════════════════════════════
     *             CONSTRUCTORS
     * ═══════════════════════════════════════ */

    /**
     * Creates a new, empty vault with the given encryption strategy.
     *
     * @param strategy the strategy used for all encrypt/decrypt operations;
     *                 must not be {@code null}
     * @throws NoSuchAlgorithmException if the strategy cannot be initialised
     *                                  due to an unsupported algorithm
     */
    public Vault(VaultEncryptingStrategy strategy, User user, boolean isEncrypted) throws GeneralSecurityException {
        this.strategy = strategy;
        this.user = user;
        this.isEncrypted = isEncrypted;

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(user.getUsername().getBytes(StandardCharsets.UTF_8));

        StringBuilder hex = new StringBuilder();
        for (byte b : hashBytes) {
            hex.append(String.format("%02x", b));
        }
        String hashedUsername = hex.toString();
        this.checker = strategy.encryptWithDerivedKey(hashedUsername);
    }

    public Vault(VaultEncryptingStrategy strategy, User user, String checker, boolean isEncrypted) throws GeneralSecurityException {
        this.strategy = strategy;
        this.user = user;
        this.checker = checker;
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
    public Vault add(Storable storable) {
        storables.add(storable);
        storables.sort(null);
        return this;
    }

    /**
     * Removes an item from the vault using {@link Object#equals} for comparison.
     * If the item is not present, this method has no effect.
     *
     * @param storable the item to remove
     */
    public Vault remove(Storable storable) {
        storables.remove(storable);
        return this;
    }

    /**
     * Encrypts all items currently stored in the vault by delegating to
     * {@link Storable#encrypt(VaultEncryptingStrategy)} for each item.
     * Sets {@link #isEncrypted} to {@code true} on success.
     *
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

    private Map<String, List<Storable>> classifyStorables() {
        Map<String, List<Storable>> map = new HashMap<>();
        for (Storable storable : storables) {
            String key = storable.category();
            map.computeIfAbsent(
                        key, k -> new ArrayList<>()
                    ).add(storable);
        }
        return map;
    }

    public String toJSON() throws GeneralSecurityException {
        StringBuilder sb = new StringBuilder();
        sb.append("{");

        sb.append("\"checker\": \"").append(checker).append("\", ");
        sb.append("\"vaultKey\": \"").append(strategy.exportVaultKey()).append("\", ");
        Map<String, List<Storable>> map = classifyStorables();
        boolean firstEntry = true;

        for (Map.Entry<String, List<Storable>> entry : map.entrySet()) {
            if (!firstEntry) sb.append(", ");
            firstEntry = false;

            sb.append("\"").append(entry.getKey()).append("\": [");

            List<Storable> storables = entry.getValue();
            for (int i = 0; i < storables.size(); i++) {
                sb.append(storables.get(i).toJSON());
                if (i < storables.size() - 1) sb.append(", ");
            }

            sb.append("]");
        }

        sb.append("}");
        return sb.toString();
    }

    @Override
    public String toString() {
        try {
            return toJSON();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;

        if (other instanceof Vault) {
            for (Storable storable : storables) {
                if (!((Vault) other).storables.contains(storable)) {
                    return false;
                }
            }
        }

        return true;
    }
}
