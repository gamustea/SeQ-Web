package com.seq.acheron.vault.storables;

import com.seq.acheron.agents.User;
import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import lombok.Getter;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

/**
 * Abstract base class representing an object stored in the vault.
 * <p>
 * A {@code VaultObject} provides common functionality for entities that can be:
 * <ul>
 *     <li>Encrypted and decrypted using a {@link VaultEncryptingStrategy}.</li>
 *     <li>Shared with specific users via access control lists.</li>
 *     <li>Uniquely identified within the vault.</li>
 * </ul>
 * Concrete subclasses (e.g., {@code Account}, {@code CreditCard}) define
 * which fields are considered sensitive and how to transform them.
 *
 * @see Storable
 * @see Sharable
 */
public abstract class VaultObject implements Sharable, Storable {

    /**
     * Unique identifier for this vault object.
     * <p>
     * The ID is composed of a type-specific code (e.g., {@code "ACC"} for accounts,
     * {@code "CDC"} for credit cards) followed by a sequential number assigned
     * at construction time.
     */
    @Getter
    private final String id;

    /**
     * Set of users who are allowed to access this vault object.
     * <p>
     * Access control is managed via {@link #isAllowed(User)} and {@link #revoke(User)}.
     */
    @Getter
    private final Set<User> allowedUsers;

    /**
     * Global counter used to assign unique sequential numbers to vault objects.
     * <p>
     * <b>Warning:</b> This counter is shared across all {@code VaultObject} instances.
     * Modifying it directly may result in ID collisions.
     */
    @Getter
    @Setter
    private static int objectCounter = 0;

    /**
     * Indicates whether the sensitive fields of this object are currently encrypted.
     * <p>
     * This flag is updated automatically by {@link #encrypt(VaultEncryptingStrategy)}
     * and {@link #decrypt(VaultEncryptingStrategy)}.
     */
    @Getter
    protected boolean isEncrypted;

    /**
     * Creates a new vault object with a unique identifier.
     *
     * @param code        the type-specific code prefix (e.g., {@code "ACC"}, {@code "CDC"})
     * @param isEncrypted {@code true} if the fields being stored are already encrypted
     *                    (e.g., when loading from persistent storage);
     *                    {@code false} if they are plain-text
     */
    public VaultObject(String code, boolean isEncrypted) {
        this.id = code + objectCounter;
        this.allowedUsers = new HashSet<>();
        this.isEncrypted = isEncrypted;
        objectCounter++;
    }

    /**
     * Encrypts all sensitive fields of this object using the provided strategy.
     * <p>
     * This method delegates to {@link #transform(VaultEncryptingStrategy, boolean)}
     * with {@code encrypt = true} and updates {@link #isEncrypted} accordingly.
     *
     * @param encryptor the encryption strategy to use
     * @return a string representation of the object's state <b>before</b> encryption
     * @throws IllegalStateException if the object is already encrypted
     * @see #decrypt(VaultEncryptingStrategy)
     */
    @Override
    public String encrypt(VaultEncryptingStrategy encryptor) {
        if (isEncrypted) {
            throw new IllegalStateException("Cannot encrypt: object is already encrypted (id=" + id + ")");
        }
        return transform(encryptor, true);
    }

    /**
     * Decrypts all sensitive fields of this object using the provided strategy.
     * <p>
     * This method delegates to {@link #transform(VaultEncryptingStrategy, boolean)}
     * with {@code encrypt = false} and updates {@link #isEncrypted} accordingly.
     *
     * @param encryptor the encryption strategy to use; must be compatible with
     *                  the one used for encryption
     * @return a string representation of the object's state <b>before</b> decryption
     * @throws IllegalStateException if the object is not encrypted
     * @see #encrypt(VaultEncryptingStrategy)
     */
    @Override
    public String decrypt(VaultEncryptingStrategy encryptor) {
        if (!isEncrypted) {
            throw new IllegalStateException("Cannot decrypt: object is not encrypted (id=" + id + ")");
        }
        return transform(encryptor, false);
    }

    /**
     * Checks whether the specified user is allowed to access this vault object.
     *
     * @param user the user to check
     * @return {@code true} if the user is in the allowed users set; {@code false} otherwise
     */
    @Override
    public boolean isAllowed(User user) {
        return allowedUsers.contains(user);
    }

    /**
     * Revokes access to this vault object for the specified user.
     *
     * @param user the user whose access should be revoked
     * @return {@code true} if the user was removed from the allowed users set;
     *         {@code false} if the user was not in the set
     */
    @Override
    public boolean revoke(User user) {
        return allowedUsers.remove(user);
    }

    /**
     * Compares this vault object to another object for equality.
     * <p>
     * Two vault objects are considered equal if they have the same {@link #id}.
     *
     * @param obj the object to compare
     * @return {@code true} if the objects have the same ID; {@code false} otherwise
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }

        if (!(obj instanceof VaultObject)) {
            return false;
        }

        String otherId = ((VaultObject) obj).id;
        return this.id.equals(otherId);
    }

    /**
     * Returns a hash code for this vault object based on its {@link #id}.
     * <p>
     * This method is consistent with {@link #equals(Object)} to ensure correct
     * behavior in hash-based collections.
     *
     * @return the hash code of the object's ID
     */
    @Override
    public int hashCode() {
        return id.hashCode();
    }

    /**
     * Transforms (encrypts or decrypts) all sensitive fields of this object.
     * <p>
     * Implementations should:
     * <ul>
     *     <li>Create a copy of the current object state using {@link #copy()}.</li>
     *     <li>Apply the encryption or decryption operation to all sensitive fields.</li>
     *     <li>Update {@link #isEncrypted} to reflect the new state.</li>
     *     <li>Return the string representation of the <b>old</b> (pre-transformation) state.</li>
     * </ul>
     *
     * @param encryptor the encryption strategy to use
     * @param encrypt   {@code true} to encrypt fields; {@code false} to decrypt them
     * @return a string representation of the object's state before transformation
     */
    abstract String transform(VaultEncryptingStrategy encryptor, boolean encrypt);

    /**
     * Creates a deep copy of this vault object with the same field values.
     * <p>
     * This method is used internally by {@link #transform(VaultEncryptingStrategy, boolean)}
     * to preserve the object's state before encryption or decryption.
     * <p>
     * Implementations should copy all fields, including {@link #isEncrypted},
     * to ensure the snapshot accurately reflects the current state.
     *
     * @return a new instance of the same type with identical field values
     */
    abstract VaultObject copy();
}
