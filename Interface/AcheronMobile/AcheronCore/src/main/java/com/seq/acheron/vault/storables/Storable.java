package com.seq.acheron.vault.storables;

import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.Vault;

/**
 * Represents an entity that contains one or more secrets which can be
 * encrypted and decrypted using an {@link VaultEncryptingStrategy}.
 * <p>
 * Implementations decide which fields are considered secret and how they
 * are transformed internally (for example, storing an encrypted password
 * as Base64).
 */
public interface Storable {

    /**
     * Returns a unique identification code based on the object
     * type of the caller instance. The allowed codes in the system
     * are:
     * <ul>
     *     <li>{@code CDC}: for cards</li>
     *     <li>{@code ACC}: for accounts</li>
     * </ul>
     * A code is allways followed by a number. These numbers are incrementally
     * assigned to each of the instances.
     * @return Unique identification for the caller instance.
     */
    String getId();

     /**
      * Encrypts the sensitive data of this entity using the provided
      * encryption strategy. The caller instance of {@link VaultObject}
      * would result in a Base-64, encrypted version of the entity.
      *
      * @param encryptingStrategy the encryption strategy to use
      * @return a human-readable representation of the
      * previous state of the object
      * (for example, its {@link Object#toString()} value)
      * before applying encryption.
      */
    String encrypt(VaultEncryptingStrategy encryptingStrategy);

    /**
     * Decrypts the sensitive data of this entity using the provided
     * encryption strategy. The caller instance of {@link VaultObject}
     * would result in the decrypted version of the entity.
     * <p><b>Warning:</b> the information stored inside the entity,
     * previous to the encryption, MUST be in Base-64</p>
     *
     * @param encryptingStrategy the encryption strategy to use;
     *                           must be compatible with the one used
     *                           for {@link #encrypt(VaultEncryptingStrategy)}
     * @return the encrypted representation of the object previous to the process
     * in a Base-64 encoding.
     */
    String decrypt(VaultEncryptingStrategy encryptingStrategy);

    /**
     * Checks if the information stored in the entity is
     * encrypted or not.
     * @return True if it's encrypted and false otherwise.
     */
    boolean isEncrypted();

    String toJSON();
}
