
package com.seq.acheron.vault.storables;

import com.google.gson.JsonObject;
import com.seq.acheron.util.CryptoUtils;
import com.seq.acheron.vault.User;
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.util.Pair;
import com.seq.acheron.vault.interfaces.JsonSerializable;
import com.seq.acheron.vault.interfaces.Sharable;
import com.seq.acheron.vault.interfaces.Storable;
import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;

import java.security.GeneralSecurityException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Abstract base class representing an object stored in the vault.
 * <p>
 * A {@code VaultObject} provides common functionality for entities that can be:
 * <ul>
 * <li>Encrypted and decrypted using a {@link VaultEncryptingStrategy}.</li>
 * <li>Shared with specific users via access control lists.</li>
 * <li>Uniquely identified within the vault.</li>
 * </ul>
 * Concrete subclasses (e.g., {@code Account}) define
 * which fields are considered sensitive and how to transform them.
 */
public abstract class VaultObject implements Sharable, Storable, JsonSerializable, Comparable<VaultObject> {

    @Getter
    protected String id;

    @Getter @Setter
    protected String title;

    @Getter
    protected final Set<User> allowedUsers;

    @Getter
    protected boolean isEncrypted;

    @Getter
    protected final Date createdAt;

    @Getter @Setter
    protected Date updatedAt;

    private String pendingPrefix;

    /**
     * Generates a unique ID from the encrypted JSON content of a storable using SHA256.
     * <p>
     * The generated ID is deterministic: the same content always produces the same ID.
     * This enables collision-free offline synchronization across multiple devices.
     *
     * @param encryptedJson the encrypted JSON representation of the storable
     * @return a 16-character hexadecimal string (128 bits) derived from SHA256
     * @throws RuntimeException if SHA256 is not available (should never happen on Android)
     */
    public static String generateIdFromContent(@NotNull String encryptedJson) {
        try {
            return CryptoUtils.sha256Hex(encryptedJson).substring(0, 16);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("SHA-256 hash algorithm not available", e);
        }
    }

    public VaultObject(String code, String title, boolean isEncrypted, boolean needsAutoId) {
        this(code, title, isEncrypted, new Date(), new Date(), needsAutoId);
    }

    public VaultObject(String code, String title, boolean isEncrypted, Date createdAt, Date updatedAt, boolean needsAutoId) {
        if (needsAutoId) {
            this.id = null;
            this.pendingPrefix = code;
        } else {
            this.id = code;
            this.pendingPrefix = null;
        }
        this.title = title;
        this.allowedUsers = new HashSet<>();
        this.isEncrypted = isEncrypted;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public boolean needsIdAssignment() {
        return pendingPrefix != null;
    }

    /**
     * Assigns an ID directly (used for hash-based IDs).
     *
     * @param id the complete ID (e.g., a 16-char hash)
     */
    public void assignIdDirect(String id) {
        Objects.requireNonNull(id, "id must not be null");
        this.id = id;
        this.pendingPrefix = null;
    }

    @Override
    public String encrypt(VaultEncryptingStrategy encryptor) {
        if (isEncrypted) {
            throw new IllegalStateException("Cannot encrypt: object is already encrypted (id=" + id + ")");
        }
        return transform(encryptor, true);
    }

    @Override
    public String decrypt(VaultEncryptingStrategy encryptor) {
        if (!isEncrypted) {
            throw new IllegalStateException("Cannot decrypt: object is not encrypted (id=" + id + ")");
        }
        return transform(encryptor, false);
    }

    String transform(VaultEncryptingStrategy encryptor, boolean encrypt) {
        String snapshot = toString();
        title = apply(encryptor, encrypt, title);
        isEncrypted = encrypt;
        return snapshot;
    }

    /**
     * Encrypts or decrypts a single field value with the given strategy,
     * re-throwing any {@link GeneralSecurityException} as an unchecked
     * {@link RuntimeException}. Subclasses use this to transform their own
     * sensitive fields without repeating the try/catch boilerplate.
     *
     * @param encryptor the strategy to use
     * @param encrypt   {@code true} to encrypt the value, {@code false} to decrypt it
     * @param value     the field value to transform
     * @return the transformed value
     */
    protected String apply(VaultEncryptingStrategy encryptor, boolean encrypt, String value) {
        try {
            return encrypt ? encryptor.encrypt(value) : encryptor.decrypt(value);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to transform vault object fields", e);
        }
    }

    /**
     * Resolves what a sensitive field should render as in {@link #toJson()},
     * depending on this object's current {@link #isEncrypted} state.
     * <p>
     * {@code toJson()} intentionally serves two purposes with a single, always-safe
     * representation: while encrypted, {@code rawValue} is cipher-text — safe to
     * persist or transmit as-is (this is the path {@link com.seq.acheron.vault.Vault}
     * relies on to serialise items); while decrypted, the true {@code rawValue} must
     * never leave this object, so {@code displayValue} (e.g. {@code "***"} or a masked
     * tail) is shown instead. This helper makes that decision explicit at each call
     * site instead of repeating the {@code isEncrypted ? raw : masked} ternary.
     *
     * @param rawValue     the field's current value (cipher-text once encrypted)
     * @param displayValue the safe stand-in to show while the field still holds plain-text
     * @return {@code rawValue} if {@link #isEncrypted}, otherwise {@code displayValue}
     */
    protected String revealOrMask(String rawValue, String displayValue) {
        return isEncrypted ? rawValue : displayValue;
    }

    @Override
    public boolean isAllowed(User user) {
        return allowedUsers.contains(user);
    }

    @Override
    public boolean revoke(User user) {
        return allowedUsers.remove(user);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof VaultObject other)) return false;
        return Objects.equals(this.id, other.id);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(id);
    }

    public Pair<String, String> sliceCode() {
        StringBuilder letters = new StringBuilder();
        StringBuilder numbers = new StringBuilder();
        for (int i = 0; i < id.length(); i++) {
            char c = id.charAt(i);
            if (Character.isDigit(c)) {
                numbers.append(id.substring(i));
                break;
            }
            letters.append(c);
        }
        return new Pair<>(letters.toString(), numbers.toString());
    }

    @Override
    public int compareTo(@NotNull VaultObject other) {
        Pair<String, String> thisCode = this.sliceCode();
        Pair<String, String> otherCode = other.sliceCode();
        if (!thisCode.left().equals(otherCode.left())) {
            return thisCode.left().compareTo(otherCode.left());
        }
        try {
            int thisInt = Integer.parseInt(thisCode.right());
            int otherInt = Integer.parseInt(otherCode.right());
            return Integer.compare(thisInt, otherInt);
        } catch (NumberFormatException e) {
            return this.id.compareTo(other.id);
        }
    }

    @Override
    public String toString() {
        return this.toJson();
    }

    @Override
    public String toJson() {
        JsonObject json = toJsonObject();
        return json.toString();
    }

    JsonObject toJsonObject() {
        JsonObject json = new JsonObject();
        json.addProperty("id", this.id);
        json.addProperty("title", this.title);

        String createdAtISO = DateTimeFormatter.ISO_OFFSET_DATE_TIME
                .format(this.createdAt.toInstant().atZone(ZoneId.systemDefault()));
        String updatedAtISO = DateTimeFormatter.ISO_OFFSET_DATE_TIME
                .format(this.updatedAt.toInstant().atZone(ZoneId.systemDefault()));

        json.addProperty("createdAt", createdAtISO);
        json.addProperty("updatedAt", updatedAtISO);

        List<String> userIds = allowedUsers.stream()
                .map(User::getId)
                .sorted()
                .toList();
        com.google.gson.JsonArray userArray = new com.google.gson.JsonArray();
        for (String uid : userIds) {
            userArray.add(uid);
        }
        json.add("allowedUsers", userArray);

        return json;
    }

}
