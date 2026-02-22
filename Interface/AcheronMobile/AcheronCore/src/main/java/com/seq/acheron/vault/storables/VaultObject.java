
package com.seq.acheron.vault.storables;

import com.seq.acheron.vault.User;
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.util.Pair;
import com.seq.acheron.vault.interfaces.JsonSerializable;
import com.seq.acheron.vault.interfaces.Sharable;
import com.seq.acheron.vault.interfaces.Storable;
import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;

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

    @Getter @Setter
    protected String title;

    @Getter
    protected final String id;

    @Getter
    protected final Set<User> allowedUsers;

    @Getter @Setter
    protected static int objectCounter = 0;

    @Getter
    protected boolean isEncrypted;

    @Getter
    protected final Date createdAt;

    @Getter @Setter
    protected Date updatedAt;

    public VaultObject(String code, String title, boolean isEncrypted, boolean increaseCounter) {
        this(code, title, isEncrypted, new Date(), new Date(), increaseCounter);
    }

    public VaultObject(String code, String title, boolean isEncrypted, Date createdAt, Date updatedAt, boolean increaseCounter) {
        this.id = increaseCounter ? code + objectCounter : code;
        this.title = title;
        this.allowedUsers = new HashSet<>();
        this.isEncrypted = isEncrypted;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        if (increaseCounter) objectCounter++;
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
        String createdAtISO = DateTimeFormatter.ISO_OFFSET_DATE_TIME
                .format(this.createdAt.toInstant().atZone(ZoneId.systemDefault()));
        String updatedAtISO = DateTimeFormatter.ISO_OFFSET_DATE_TIME
                .format(this.updatedAt.toInstant().atZone(ZoneId.systemDefault()));

        List<String> userIds = allowedUsers.stream()
                .map(User::getId)
                .sorted()
                .toList();

        StringBuilder userList = new StringBuilder("[");
        for (int i = 0; i < userIds.size(); i++) {
            userList.append("\"").append(userIds.get(i)).append("\"");
            if (i < userIds.size() - 1) userList.append(", ");
        }
        userList.append("]");

        return "\"id\": \"" + this.id + "\", "
                + "\"title\": \"" + this.title + "\", "
                +"\"createdAt\": \"" + createdAtISO + "\", "
                + "\"updatedAt\": \"" + updatedAtISO + "\", "
                + "\"allowedUsers\": " + userList + ", ";
    }

    abstract String transform(VaultEncryptingStrategy encryptor, boolean encrypt);
}
