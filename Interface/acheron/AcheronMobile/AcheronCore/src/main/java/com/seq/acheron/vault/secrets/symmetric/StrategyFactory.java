// com/seq/acheron/vault/secrets/symmetric/StrategyFactory.java
package com.seq.acheron.vault.secrets.symmetric;

import com.google.gson.JsonObject;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

/**
 * Factory contract for constructing a {@link VaultEncryptingStrategy}
 * from a JSON descriptor and cryptographic material.
 *
 * <p>Implement this interface for each KDF/cipher combination and
 * register it in {@link StrategyRegistry}.
 */
@FunctionalInterface
public interface StrategyFactory {

    /**
     * Reconstructs a strategy from persisted parameters.
     *
     * @param masterPassword the user's master password (will be wiped by the impl)
     * @param algorithmJson  the {@code "algorithm"} JSON object from the vault file
     * @param vaultKey       the already-unwrapped vault key, or {@code null} on first creation
     * @return a fully initialised {@link VaultEncryptingStrategy}
     */
    VaultEncryptingStrategy create(
            String masterPassword,
            JsonObject algorithmJson,
            SecretKey vaultKey
    ) throws GeneralSecurityException;
}
