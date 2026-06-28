package com.seq.acheron.vault;

import com.seq.acheron.exceptions.WrongPasswordException;
import com.seq.acheron.util.CryptoUtils;
import com.seq.acheron.vault.interfaces.Cypher;
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.interfaces.JsonSerializable;
import com.seq.acheron.vault.interfaces.Storable;
import com.seq.acheron.vault.storables.VaultObject;

import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
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

    public static final int VAULT_VERSION = 1;

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
     * <p>
     * Mutable: it is recomputed by {@link #changePassword(String, String)} when
     * the master password is rotated.
     */
    private String checker;

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



    /* ────────────────────────────────────
     *              ACCESSORS
     * ──────────────────────────────────── */

    /** @return the owner of this vault */
    public User getUser() {
        return user;
    }

    /** @return the encrypted password verifier bound to the master password */
    public String getChecker() {
        return checker;
    }

    /**
     * @return {@code true} if the items currently hold cipher-text;
     *         {@code false} if they hold plain-text
     */
    public boolean isEncrypted() {
        return isEncrypted;
    }

    /**
     * Returns a read-only view of the stored items. Use {@link #add(Storable)}
     * and {@link #remove(Storable)} to change the contents; the encryption
     * {@link #strategy} (which holds key material) is intentionally not exposed.
     *
     * @return an unmodifiable list of the stored items
     */
    public List<Storable> getStorables() {
        return Collections.unmodifiableList(storables);
    }


    /* ────────────────────────────────────
     *              CRUD
     * ──────────────────────────────────── */

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
     * If the storable was constructed with auto-ID generation
     * ({@link VaultObject#needsIdAssignment()}), a deterministic content-based
     * ID is assigned (see {@link #assignContentBasedId(VaultObject)}). Items
     * loaded with an explicit ID (e.g. from {@code fromJson}) keep it.
     * <p>
     * After insertion, the internal list of items is re-sorted according to
     * the natural ordering of {@link Storable}.
     *
     * @param storable the item to add; must not be {@code null}
     * @return this vault instance, for fluent usage
     */
    public Vault add(Storable storable) {
        Objects.requireNonNull(storable, "storable must not be null");
        if (storable instanceof VaultObject vo && vo.needsIdAssignment()) {
            assignContentBasedId(vo);
        }
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


    /* ────────────────────────────────────
     *        ENCRYPTION LIFECYCLE
     * ──────────────────────────────────── */

    /**
     * Encrypts all items currently stored in the vault by delegating to
     * {@link Cypher#encrypt(VaultEncryptingStrategy)} for each item.
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
     * {@link Cypher#decrypt(VaultEncryptingStrategy)} for each item.
     * Sets {@link #isEncrypted} to {@code false} on success.
     *
     * @return this vault instance, for fluent usage
     * @throws IllegalStateException if the vault is not currently encrypted
     */
    public Vault decryptAll() {
        return toggleEncrypt(false);
    }

    /**
     * Rotates the master password protecting this vault.
     * <p>
     * Thanks to envelope encryption, only the key-encryption material changes:
     * the random {@link VaultEncryptingStrategy#getVaultKey() vaultKey} that
     * actually encrypts every item is preserved, so the stored ciphertext of
     * the items is untouched. The operation:
     * <ol>
     *   <li>requires the vault to be <b>decrypted</b> (so it is genuinely
     *       unlocked and the current derived key is available);</li>
     *   <li>verifies that {@code oldPassword} is the current master password;</li>
     *   <li>re-derives the key from {@code newPassword} using a freshly
     *       generated salt, re-wrapping the same {@code vaultKey};</li>
     *   <li>recomputes the {@link #checker} bound to the new derived key.</li>
     * </ol>
     * After this returns, call {@link #encryptAll()} and {@link #toJson()} to
     * obtain a persistable representation bound to the new password.
     *
     * @param oldPassword the current master password
     * @param newPassword the new master password
     * @return this vault instance, for fluent usage
     * @throws IllegalStateException    if the vault is currently encrypted
     * @throws WrongPasswordException   if {@code oldPassword} is not the current
     *                                  master password
     * @throws GeneralSecurityException if key derivation or checker computation fails
     */
    public Vault changePassword(String oldPassword, String newPassword)
            throws GeneralSecurityException, WrongPasswordException {
        Objects.requireNonNull(oldPassword, "oldPassword must not be null");
        Objects.requireNonNull(newPassword, "newPassword must not be null");

        if (isEncrypted) {
            throw new IllegalStateException(
                    "Vault must be decrypted to change the master password");
        }
        if (!strategy.matchesPassword(oldPassword)) {
            throw new WrongPasswordException("Wrong current master password");
        }

        String newSalt = CryptoUtils.generateSalt();
        strategy.changePassword(newPassword, newSalt);
        this.checker = strategy.getChecker(user.getUsername());
        return this;
    }

    /**
     * Produces the encrypted JSON of a single stored item <b>without</b>
     * mutating the live, decrypted item.
     * <p>
     * The vault must currently be decrypted. The target item is located by its
     * {@link Storable#getId() id}, {@link Storable#copy() copied}, and only the
     * copy is encrypted using this vault's {@link VaultEncryptingStrategy}; the
     * in-memory item is left untouched in plain-text state.
     * <p>
     * This enables surgical, per-item updates: the caller can ship just one
     * item's ciphertext to the server (e.g. to a partial-update endpoint keyed
     * by the item's id) instead of re-encrypting and re-uploading the whole
     * vault for every single change.
     *
     * @param id the id of the item to export (e.g. {@code "ACC0"}, {@code "CDC1"})
     * @return the encrypted JSON representation of the matching item
     * @throws IllegalStateException   if the vault is currently encrypted
     * @throws NoSuchElementException  if no item matches {@code id}
     */
    public String exportEncryptedStorable(String id) {
        Objects.requireNonNull(id, "id must not be null");
        if (isEncrypted) {
            throw new IllegalStateException(
                    "Vault must be decrypted to export a single storable");
        }

        Storable target = get(id);
        if (target == null) {
            throw new NoSuchElementException("No storable with id " + id);
        }

        Storable copy = target.copy();
        copy.encrypt(strategy);
        return copy.toJson();
    }


    /* ────────────────────────────────────
     *           SERIALIZATION
     * ──────────────────────────────────── */

    /**
     * Serialises this vault to a JSON string suitable for persistence.
     * <p>
     * The vault MUST be encrypted before calling this method; an
     * {@link IllegalStateException} is thrown otherwise to prevent
     * accidental export of plain-text secrets.
     * <p>
     * The JSON includes:
     * <ul>
     *   <li>{@code checker}: the encrypted verifier bound to the master password.</li>
     *   <li>{@code vaultKey}: the exported key material from
     *       {@link VaultEncryptingStrategy#exportVaultKey()}.</li>
     *   <li>One array per {@link Storable#category()}, containing the JSON form
     *       of each stored item (ciphertext).</li>
     * </ul>
     *
     * @return JSON representation of this vault
     * @throws IllegalStateException     if the vault is not encrypted
     * @throws GeneralSecurityException if exporting the vault key fails
     */
    public String toJson() throws GeneralSecurityException {
        if (!isEncrypted) {
            throw new IllegalStateException("Vault must be encrypted before serialisation");
        }

        JsonObject root = new JsonObject();
        root.addProperty("version", VAULT_VERSION);
        root.addProperty("checker", checker);
        root.addProperty("vaultKey", strategy.exportVaultKey());
        root.add("algorithm", JsonParser.parseString(strategy.toJson()));

        Map<String, List<Storable>> map = classifyStorables();
        for (Map.Entry<String, List<Storable>> entry : map.entrySet()) {
            JsonArray array = new JsonArray();
            for (Storable storable : entry.getValue()) {
                array.add(JsonParser.parseString(storable.toJson()));
            }
            root.add(entry.getKey(), array);
        }

        return root.toString();
    }


    /* ────────────────────────────────────
     *         OBJECT OVERRIDES
     * ──────────────────────────────────── */

    /**
     * Returns a safe debug representation.  Only returns the full JSON
     * when the vault is encrypted; otherwise shows a summary.
     */
    @Override
    public String toString() {
        if (!isEncrypted) {
            return "Vault{storables=" + storables.size() + ", encrypted=false}";
        }
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
                && Objects.equals(user, that.user)
                && Objects.equals(checker, that.checker)
                && Objects.equals(storables, that.storables);
    }

    @Override
    public int hashCode() {
        return Objects.hash(user, checker, storables, isEncrypted);
    }


    /* ────────────────────────────────────
     *         INTERNAL HELPERS
     * ──────────────────────────────────── */

    /**
     * Applies the encrypt or decrypt operation to every stored item and
     * updates {@link #isEncrypted}.
     *
     * @param encrypt {@code true} to encrypt all items; {@code false} to decrypt
     * @return this vault instance
     * @throws IllegalStateException if the operation conflicts with the current
     *                               {@link #isEncrypted} state
     */
    private Vault toggleEncrypt(boolean encrypt) {
        final boolean cannotEncrypt = encrypt && isEncrypted;
        final boolean cannotDecrypt = !encrypt && !isEncrypted;
        if (cannotEncrypt || cannotDecrypt) {
            throw new IllegalStateException(
                "Vault is already " + (
                    encrypt ?
                    "encrypted" : 
                    "decrypted"
                ) + "."
            );
        }

        for (Cypher storable : storables) {
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
     * Assigns a deterministic, content-based ID to a freshly created item.
     * <p>
     * {@link VaultObject#copy()} and {@code toJson()} require a non-null id, so a
     * temporary placeholder is set first; the item's encrypted JSON is then
     * hashed and the resulting 16-char hash becomes the final ID. Hashing a
     * throwaway encrypted copy leaves the live, plain-text item untouched.
     *
     * @param vo a vault object that still needs an ID assigned
     */
    private void assignContentBasedId(VaultObject vo) {
        vo.assignIdDirect("");
        Storable copy = vo.copy();
        ((Cypher) copy).encrypt(strategy);
        String hashId = VaultObject.generateIdFromContent(copy.toJson());
        vo.assignIdDirect(hashId);
    }
}
