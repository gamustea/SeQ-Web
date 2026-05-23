package com.seq.acheron.vault.interfaces;

import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;

public interface Cypher {

    /**
     * Returns whether this entry's sensitive fields are currently encrypted.
     *
     * @return {@code true} if the fields hold cipher-text; {@code false} if
     *         they hold plain-text
     */
    boolean isEncrypted();

    /**
     * Encrypts all sensitive fields of this entry using the provided strategy.
     * <p>
     * After this call, the encrypted fields will hold Base64-encoded
     * {@code IV || ciphertext} values. The entry's internal {@code isEncrypted}
     * flag is set to {@code true}.
     *
     * @param encryptingStrategy the encryption strategy to use; must not be
     *                           {@code null}
     * @return a human-readable snapshot of the object's state
     *         <b>before</b> encryption (e.g. its {@code toString()} value)
     * @throws IllegalStateException if the entry is already encrypted
     */
    String encrypt(VaultEncryptingStrategy encryptingStrategy);


    /**
     * Decrypts all sensitive fields of this entry using the provided strategy.
     * <p>
     * The strategy used here must be compatible with the one used during
     * {@link #encrypt}. After this call, the fields will hold plain-text values
     * and the internal {@code isEncrypted} flag is set to {@code false}.
     *
     * @param encryptingStrategy the decryption strategy to use; must match
     *                           the one used for encryption
     * @return a snapshot of the object's encrypted state
     *         <b>before</b> decryption
     * @throws IllegalStateException if the entry is not encrypted
     */
    String decrypt(VaultEncryptingStrategy encryptingStrategy);
}
