package com.seq.acheron.vault;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.seq.acheron.exceptions.WrongPasswordException;
import com.seq.acheron.vault.secrets.symmetric.Argon2VaultEncryptingStrategy;
import com.seq.acheron.vault.secrets.symmetric.PBKDF2VaultEncryptingStrategy;

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
    private static final String MOCK_VAULT_PASSWD = "Contraseña";

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
    public Vault getMockVault() throws GeneralSecurityException {
        return getMockVault(user);
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
    public Vault getMockVault(User user) throws GeneralSecurityException {
        Objects.requireNonNull(user, "user must not be null");

        Vault vault = new Vault(new PBKDF2VaultEncryptingStrategy(
                    MOCK_VAULT_PASSWD,
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

        String salt = algorithmJson.get("salt").getAsString();

        VaultEncryptingStrategy strategy = buildStrategy(kdfId, masterPassword, salt);
        String checker = root
                .get("checker")
                .getAsString();

        if (!checkMasterPassword(checker, strategy)) {
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

        if (root.has("accounts")) {
            JsonArray accounts = root.getAsJsonArray("accounts");
            for (JsonElement element : accounts) {
                vault.add(Account.fromJson(element.getAsJsonObject()));
            }
        }

        if (root.has("creditcards")) {
            JsonArray creditCards = root.getAsJsonArray("creditcards");
            for (JsonElement element : creditCards) {
                vault.add(CreditCard.fromJson(element.getAsJsonObject()));
            }
        }

        return vault;
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


    private static VaultEncryptingStrategy buildStrategy(
            @NotNull String kdfId,
            @NotNull String masterPassword,
            @NotNull String salt
    ) throws GeneralSecurityException {
        if ("PBKDF2".equalsIgnoreCase(kdfId)) {
            return new PBKDF2VaultEncryptingStrategy(masterPassword, salt, (SecretKey) null);
        }
        return new Argon2VaultEncryptingStrategy(masterPassword, salt, (SecretKey) null);
    }

}
