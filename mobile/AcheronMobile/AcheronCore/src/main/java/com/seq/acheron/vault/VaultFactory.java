package com.seq.acheron.vault;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.seq.acheron.exceptions.AcheronException;
import com.seq.acheron.exceptions.WrongPasswordException;
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategyFactory;
import com.seq.acheron.vault.storables.StorableTypes;
import org.jetbrains.annotations.NotNull;

import javax.crypto.AEADBadTagException;
import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * Factory responsible for building {@link Vault} instances.
 * <p>
 * Responsibilities:
 * <ul>
 *   <li>Reconstruct vaults from their JSON representation.</li>
 *   <li>Validate the master password using the {@code checker} field.</li>
 * </ul>
 * <p>
 * This implementation is intended for single-user desktop/mobile scenarios.
 * For multi-user or server-side environments, prefer creating a dedicated
 * factory instance per user.
 *
 * @param user The user this factory is bound to. All vaults produced by this instance
 *             will use this user as their logical owner and as input when validating
 *             the master password through the {@code checker} mechanism.
 */
public record VaultFactory(User user) {

    public VaultFactory(User user) {
        this.user = Objects.requireNonNull(user, "user must not be null");
    }


    /**
     * Reconstructs a {@link Vault} instance from its JSON representation.
     *
     * <p>Expected top-level JSON keys:
     * <ul>
     *   <li>{@code "version"}  — vault format version</li>
     *   <li>{@code "checker"}  — encrypted password verifier</li>
     *   <li>{@code "vaultKey"} — vault key encrypted with the derived key</li>
     *   <li>{@code "algorithm"} — object with at least a {@code "kdf"} and {@code "salt"} field</li>
     *   <li>one optional array per {@link StorableTypes#categories() registered storable
     *       category} (e.g. {@code "accounts"}, {@code "creditcards"}, ...)</li>
     * </ul>
     *
     * @param json           JSON string previously produced by {@link Vault#toJson()}
     * @param masterPassword the user's master password
     * @return a fully reconstructed, decrypted {@link Vault}
     */
    public Vault fromJson(
            @NotNull String json,
            @NotNull String masterPassword
    ) throws GeneralSecurityException, WrongPasswordException {

        JsonObject root = JsonParser.parseString(json).getAsJsonObject();

        if (root.has("version")) {
            int version = root.get("version").getAsInt();
            if (version > Vault.VAULT_VERSION) {
                throw new AcheronException(
                    "Unsupported vault version " + version + " (max " + Vault.VAULT_VERSION + ")"
                );
            }
        }

        JsonObject algorithmJson = root.getAsJsonObject("algorithm");
        String kdfId = algorithmJson.has("kdf") ?
                algorithmJson.get("kdf").getAsString() :
                "Argon2";

        if (!algorithmJson.has("salt")) {
            throw new AcheronException("Vault JSON is missing algorithm.salt");
        }
        String salt = algorithmJson.get("salt").getAsString();

        int kdfIterations = parseIntOrZero(algorithmJson, "kdfIterations");
        int kdfMemoryKiB   = parseIntOrZero(algorithmJson, "kdfMemoryKiB");
        int kdfParallelism = parseIntOrZero(algorithmJson, "kdfParallelism");

        VaultEncryptingStrategy strategy = buildStrategy(kdfId, masterPassword, salt,
                kdfIterations, kdfMemoryKiB, kdfParallelism);
        String checker = root
                .get("checker")
                .getAsString();

        if (!isValidMasterPassword(checker, strategy)) {
            throw new WrongPasswordException("Wrong master password");
        }

        String vaultKeyStr = root.get("vaultKey").getAsString();
        try {
            strategy.importVaultKey(vaultKeyStr);
        } catch (AEADBadTagException e) {
            throw new WrongPasswordException("Decrypting Vault with wrong password attempt");
        }

        Vault vault = new Vault(
                strategy,
                user,
                checker,
                true
        );

        for (String category : StorableTypes.categories()) {
            if (root.has(category)) {
                for (JsonElement element : root.getAsJsonArray(category)) {
                    vault.add(StorableTypes.fromJson(category, element.getAsJsonObject()));
                }
            }
        }

        return vault;
    }


    /**
     * Validates the supplied master password against the stored {@code checker}.
     * <p>
     * Delegates to {@link VaultEncryptingStrategy#isValidChecker(String, String)},
     * which owns the derived key and performs the constant-time comparison; an
     * incorrect master password (failed AEAD tag) is reported as {@code false}
     * rather than propagated as a generic cryptographic error.
     *
     * @param checker  encrypted verifier stored alongside the vault
     * @param strategy strategy configured with the candidate master password
     * @return {@code true} if the master password is correct, {@code false} otherwise
     */
    private boolean isValidMasterPassword(
            @NotNull String checker,
            @NotNull VaultEncryptingStrategy strategy
    ) throws GeneralSecurityException {
        try {
            return strategy.isValidChecker(checker, user.getUsername());
        } catch (AEADBadTagException e) {
            // Wrong master key: not a generic cryptographic error.
            return false;
        }
    }


    private static VaultEncryptingStrategy buildStrategy(
            @NotNull String kdfId,
            @NotNull String masterPassword,
            @NotNull String salt,
            int iterations,
            int memoryKiB,
            int parallelism
    ) throws GeneralSecurityException {
        return VaultEncryptingStrategyFactory.reopen(kdfId, masterPassword, salt,
                iterations, memoryKiB, parallelism);
    }

    private static int parseIntOrZero(JsonObject obj, String key) {
        if (!obj.has(key)) return 0;
        JsonElement el = obj.get(key);
        if (el.isJsonPrimitive()) {
            try {
                return el.getAsInt();
            } catch (NumberFormatException e) {
                return 0;
            }
        }
        return 0;
    }
}
