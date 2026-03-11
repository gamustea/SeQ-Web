// com/seq/acheron/vault/secrets/symmetric/StrategyRegistry.java
package com.seq.acheron.vault.secrets.symmetric;

import com.google.gson.JsonObject;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Central registry that maps KDF identifiers (e.g. {@code "Argon2"}, {@code "PBKDF2"})
 * to their corresponding {@link StrategyFactory}.
 *
 * <p>New encryption strategies can be supported at runtime by calling
 * {@link #register(String, StrategyFactory)} — no existing code needs to change.
 *
 * <p>The registry is pre-populated with the built-in strategies in the
 * static initializer. Registrations are <em>not</em> thread-safe by default;
 * if concurrent registration is required, synchronise externally.
 */
public final class StrategyRegistry {

    private static final Map<String, StrategyFactory> REGISTRY = new HashMap<>();

    static {
        // ── Built-in registrations ──────────────────────────────────────────
        register("Argon2", (password, json, vaultKey) -> {
            String salt = json.get("salt").getAsString();
            if (vaultKey != null) {
                return new AESVaultEncryptingStrategy(password, salt, vaultKey);
            }
            return new AESVaultEncryptingStrategy(password, salt, true);
        });

        register("PBKDF2", (password, json, vaultKey) -> {
            String salt = json.get("salt").getAsString();
            if (vaultKey != null) {
                return new PBKDF2VaultEncryptingStrategy(password, salt, vaultKey);
            }
            return new PBKDF2VaultEncryptingStrategy(password, salt, true);
        });
    }

    private StrategyRegistry() {}

    /**
     * Registers a new strategy factory under the given KDF identifier.
     * Overwrites any previously registered factory for that key.
     *
     * @param kdfId   identifier stored in the vault's {@code "kdf"} JSON field
     * @param factory factory capable of building the strategy
     */
    public static void register(String kdfId, StrategyFactory factory) {
        REGISTRY.put(kdfId, factory);
    }

    /**
     * Removes a strategy from the registry (e.g. to deprecate a weak KDF).
     *
     * @param kdfId the identifier to deregister
     */
    public static void deregister(String kdfId) {
        REGISTRY.remove(kdfId);
    }

    /**
     * Returns the set of currently registered KDF identifiers.
     */
    public static Set<String> registeredKdfs() {
        return Set.copyOf(REGISTRY.keySet());
    }

    /**
     * Resolves and invokes the factory for the given KDF identifier.
     *
     * @throws IllegalArgumentException if no factory is registered for {@code kdfId}
     */
    public static VaultEncryptingStrategy build(
            String kdfId,
            String masterPassword,
            JsonObject algorithmJson,
            SecretKey vaultKey
    ) throws GeneralSecurityException {
        StrategyFactory factory = REGISTRY.get(kdfId);
        if (factory == null) {
            throw new IllegalArgumentException(
                    "No strategy registered for KDF: \"" + kdfId + "\". " +
                            "Registered: " + REGISTRY.keySet()
            );
        }
        return factory.create(masterPassword, algorithmJson, vaultKey);
    }
}
