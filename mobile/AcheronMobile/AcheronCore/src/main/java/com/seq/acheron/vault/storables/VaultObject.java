
package com.seq.acheron.vault.storables;

import com.google.gson.JsonObject;
import com.seq.acheron.vault.User;
import com.seq.acheron.vault.interfaces.Cypher;
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

    public String getPendingPrefix() {
        return pendingPrefix;
    }

    public void assignId(String prefix, int seq) {
        this.id = prefix + seq;
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
        VaultObject oldVaultObject = (VaultObject) copy();

        try {
            title = encrypt ?
                    encryptor.encrypt(title) :
                    encryptor.decrypt(title);

            isEncrypted = encrypt;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Error transforming account fields", e);
        }

        return oldVaultObject.toString();
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
        return this.id.equals(other.id);
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    public Pair<String, String> sliceCode() {
        StringBuilder letras = new StringBuilder();
        StringBuilder numeros = new StringBuilder();
        for (int i = 0; i < id.length(); i++) {
            char c = id.charAt(i);
            if (Character.isDigit(c)) {
                numeros.append(id.substring(i));
                break;
            }
            letras.append(c);
        }
        return new Pair<>(letras.toString(), numeros.toString());
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
