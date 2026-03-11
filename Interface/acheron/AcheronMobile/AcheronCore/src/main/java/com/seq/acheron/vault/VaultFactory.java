package com.seq.acheron.vault;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.seq.acheron.exceptions.WrongPasswordException;
import com.seq.acheron.vault.secrets.symmetric.Argon2VaultEncryptingStrategy;
import com.seq.acheron.vault.secrets.symmetric.PBKDF2VaultEncryptingStrategy;
import com.seq.acheron.vault.secrets.symmetric.StrategyRegistry;
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.util.CryptoUtils;
import com.seq.acheron.util.Pair;
import com.seq.acheron.vault.storables.Account;
import com.seq.acheron.vault.storables.CreditCard;
import org.jetbrains.annotations.NotNull;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Objects;

import static com.seq.acheron.util.CryptoUtils.constantTimeEquals;
import static com.seq.acheron.util.CryptoUtils.generateSalt;

/**
 * Factory responsible for building {@link Vault} instances.
 * <p>
 * Responsibilities:
 * <ul>
 *   <li>Create demo vaults populated with mock data (for development and tests).</li>
 *   <li>Reconstruct vaults from their JSON representation.</li>
 *   <li>Validate the master password using the {@code checker} field.</li>
 * </ul>
 * <p>
 * This implementation is a process-wide singleton primarily intended for
 * single-user desktop/mobile scenarios and demo purposes.
 * For multi-user or server-side environments, prefer creating dedicated
 * factory instances per user instead of using the static {@link #getInstance(User)}.
 *
 * @param user The user this factory is bound to. All vaults produced by this instance
 *             will use this user as their logical owner and as input when validating
 *             the master password through the {@code checker} mechanism.
 */
public record VaultFactory(User user) {

    private static VaultFactory instance;
    private static String defaultKdf = "Argon2";

    public VaultFactory(User user) {
        this.user = Objects.requireNonNull(user, "user must not be null");
    }

    /**
     * Returns the process-wide {@link VaultFactory} instance for the given user.
     * <p>
     * On the first call, a new instance bound to {@code user} is created.
     * Subsequent calls will return the same instance, regardless of the
     * {@code user} argument. This design is suitable for single-user clients
     * but can be confusing in multi-user environments.
     *
     * @param user logical owner for vaults produced by this factory
     * @return singleton {@link VaultFactory} instance
     */
    public static VaultFactory getInstance(User user) throws GeneralSecurityException {
        if (instance == null) {
            instance = new VaultFactory(user);
        }
        return instance;
    }

    /**
     * Resets the global factory instance.
     * <p>
     * Useful in tests or when switching between users in a single process.
     */
    public static void resetInstance() {
        instance = null;
    }

    /**
     * Builds an in-memory vault populated with demo credentials for the user
     * associated with this factory.
     * <p>
     * Intended for development and UI testing only; do not persist or ship this
     * data in production builds.
     *
     * @return a demo {@link Vault} instance
     */
    public Vault mockVault() throws GeneralSecurityException {
        return mockVault(user);
    }

    /**
     * Builds an in-memory vault populated with demo credentials for the given user.
     * <p>
     * All items are created in plain-text form ({@code isEncrypted = false})
     * and the containing {@link Vault} is also marked as not encrypted.
     *
     * @param user logical owner for the returned vault
     * @return a demo {@link Vault} instance
     */
    public Vault mockVault(User user) throws GeneralSecurityException {
        Objects.requireNonNull(user, "user must not be null");

        Vault vault = new Vault(new PBKDF2VaultEncryptingStrategy(
                    "Contraseña",
                    generateSalt(),
                    true
                ),
                user,
                false
        );

        // Accounts (demo data only)
        vault.add(new Account(
                "Gmail Account",
                "user@gmail.com",
                "mail.google.com",
                "P@ssw0rd123!",
                false
        ));

        vault.add(new Account(
                "Github Account",
                "gamustea",
                "github.com",
                "Gh1t#SecurePass",
                false
        ));

        vault.add(new Account(
                "Netflix Account",
                "user@gmail.com",
                "netflix.com",
                "N3tfl1x$Pass",
                false
        ));

        // Credit Cards (demo data only)
        vault.add(new CreditCard(
                "Personal Card",
                "GABRIEL MUSTEATA",
                "4111111111111111",
                "12/27",
                "123",
                "28001",
                false
        ));

        vault.add(new CreditCard(
                "Auxiliary Card",
                "GABRIEL MUSTEATA",
                "5500005555555559",
                "08/26",
                "456",
                "28002",
                false
        ));

        return vault;
    }

    /**
     * Reconstructs a {@link Vault} instance from its JSON representation.
     *
     * <p>Expected top-level JSON keys:
     * <ul>
     *   <li>{@code "checker"}  — encrypted password verifier</li>
     *   <li>{@code "vaultKey"} — vault key encrypted with the derived key</li>
     *   <li>{@code "algorithm"} — object with at least a {@code "kdf"} field</li>
     *   <li>{@code "accounts"} — optional array of Account objects</li>
     *   <li>{@code "creditcards"} — optional array of CreditCard objects</li>
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
        JsonObject algorithmJson = root.getAsJsonObject("algorithm");
        String kdfId = algorithmJson.has("kdf") ?
                algorithmJson.get("kdf").getAsString() :
                "Argon2";

        VaultEncryptingStrategy tempStrategy = StrategyRegistry.build(kdfId, masterPassword, algorithmJson, null);
        String checker = root
                .get("checker")
                .getAsString();

        if (!checkMasterPassword(checker, tempStrategy)) {
            throw new WrongPasswordException("Wrong master password");
        }

        String vaultKeyStr = root.get("vaultKey").getAsString();
        SecretKey vaultKey;
        try {
            vaultKey = tempStrategy.importVaultKey(vaultKeyStr);
        } catch (AEADBadTagException e) {
            throw new WrongPasswordException("Decrypting Vault with wrong password attempt");
        }

        VaultEncryptingStrategy strategy = StrategyRegistry.build(
                        kdfId,
                        masterPassword,
                        algorithmJson,
                        vaultKey
                );

        Vault vault = new Vault(
                strategy,
                user,
                checker,
                true
        );

        if (root.has("accounts")) {
            JsonArray accounts = root.getAsJsonArray("accounts");
            for (JsonElement element : accounts) {
                // Usamos el método fromJson de Account (que definimos en el paso anterior)
                vault.add(Account.fromJson(element.getAsJsonObject()));
            }
        }

        if (root.has("creditcards")) {
            JsonArray creditCards = root.getAsJsonArray("creditcards");
            for (JsonElement element : creditCards) {
                // Usamos el método fromJson de CreditCard
                vault.add(CreditCard.fromJson(element.getAsJsonObject()));
            }
        }

        return vault;
    }


        /**
         * Creates a restoration {@link Vault} as a self-contained backup copy of the given vault.
         * <p>
         * The restoration vault is protected by a freshly generated, cryptographically strong
         * random password and an independent AES encryption strategy, so it can be stored or
         * transmitted safely without exposing the user's original master password.
         * All {@link com.seq.acheron.vault.storables.VaultObject VaultObject} items from
         * {@code originalVault} are deep-copied into the new vault via
         * {@link com.seq.acheron.vault.storables.VaultObject#copy()}.
         * <p>
         * Typical use cases:
         * <ul>
         *   <li>Generating a one-time recovery export before a destructive operation.</li>
         *   <li>Providing the user with a backup vault alongside a temporary password
         *       for out-of-band delivery (e.g., email, QR code).</li>
         * </ul>
         *
         * @param originalVault the source {@link Vault} whose storables are to be copied;
         *                      must not be {@code null}
         * @return a {@link Pair} where the first element is the newly created restoration
         *         {@link Vault} (encrypted with a fresh strategy) and the second element
         *         is the plain-text restoration password needed to decrypt it
         * @throws GeneralSecurityException if the AES strategy cannot be initialised or
         *                                  any cryptographic operation fails
         */
    public Pair<Vault, String> getRestorationVault(
                @NotNull Vault originalVault
    ) throws GeneralSecurityException {

        String securePassword = CryptoUtils.generatePassword(32);
        String salt = CryptoUtils.generateSalt(16);
        VaultEncryptingStrategy strategy = new Argon2VaultEncryptingStrategy(
                securePassword,
                salt,
                true
        );

        Vault restorationVault = new Vault(
                strategy,
                user,
                originalVault.isEncrypted()
        );

        originalVault.getStorables()
                .forEach(storable -> {
                    restorationVault.getStorables()
                            .add(storable.copy());
                });

        return new Pair<>(restorationVault, securePassword);
    }

    /**
     * Validates that the master password currently configured in the provided
     * {@link VaultEncryptingStrategy} matches the one used to produce the
     * given {@code checker} value.
     * <p>
     * The checker is decrypted, the SHA-256 of the current {@link User}'s
     * username is recomputed, and both values are compared using a
     * constant-time comparison to reduce timing side-channels.
     *
     * @param checker  encrypted verifier stored alongside the vault
     * @param strategy strategy configured with the candidate master password
     * @return {@code true} if the master password is correct, {@code false} otherwise
     */
    private boolean checkMasterPassword(
            @NotNull String checker,
            @NotNull VaultEncryptingStrategy strategy
    ) throws GeneralSecurityException {
        String decryptedChecker = strategy.decryptWithDerivedKey(checker);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(
                user.getUsername()
                        .getBytes(StandardCharsets.UTF_8)
        );
        StringBuilder hex = new StringBuilder();
        for (byte b : hashBytes) {
            hex.append(String.format("%02x", b));
        }

        return constantTimeEquals(hex.toString(), decryptedChecker);
    }

    /**
     * Changes the default KDF used for newly created vaults.
     * Must be a KDF registered in {@link StrategyRegistry}.
     *
     * @param kdfId e.g. "Argon2", "PBKDF2"
     */
    public static void setDefaultKdf(String kdfId) {
        if (!StrategyRegistry.registeredKdfs().contains(kdfId)) {
            throw new IllegalArgumentException("Unknown KDF: " + kdfId);
        }
        defaultKdf = kdfId;
    }

    /** Builds the default strategy for new vaults (no existing vault key). */
    private VaultEncryptingStrategy buildDefaultStrategy(String masterPassword)
            throws GeneralSecurityException {
        return StrategyRegistry.build(defaultKdf, masterPassword, new JsonObject(), null);
    }
}
