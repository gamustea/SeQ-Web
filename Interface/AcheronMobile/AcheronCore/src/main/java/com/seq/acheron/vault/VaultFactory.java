package com.seq.acheron.vault;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.seq.acheron.agents.User;
import com.seq.acheron.exceptions.WrongPasswordException;
import com.seq.acheron.secrets.symmetric.AESVaultEncryptingStrategy;
import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.util.CryptoUtils;
import com.seq.acheron.vault.storables.Account;
import com.seq.acheron.vault.storables.CreditCard;
import org.jetbrains.annotations.NotNull;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Objects;

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

    /**
     * Default encryption strategy used when creating demo/mock vaults.
     * <p>
     * This strategy is initialised with hard-coded parameters and MUST NOT be
     * used for real user data in production. It is safe to use it strictly for:
     * <ul>
     *   <li>UI demos,</li>
     *   <li>sample data,</li>
     *   <li>and local development/testing.</li>
     * </ul>
     */
    private static final VaultEncryptingStrategy DEFAULT_STRATEGY;

    static {
        try {
            DEFAULT_STRATEGY = new AESVaultEncryptingStrategy(
                    "CONTRASEÑA", // demo master password
                    CryptoUtils.generateSalt(),
                    true
            );
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to initialise default demo strategy", e);
        }
    }

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

        Vault vault = new Vault(DEFAULT_STRATEGY, user, false);

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
     * <p>
     * The method expects the JSON to contain at least:
     * <ul>
     *   <li>{@code checker}: encrypted verifier bound to the master password,</li>
     *   <li>{@code vaultKey}: key material export from the strategy,</li>
     *   <li>optionally {@code accounts} and {@code creditcards} arrays.</li>
     * </ul>
     * The supplied {@code strategy} will have its key imported from
     * {@code vaultKey} and will be used to validate the master password
     * against the {@code checker}.
     *
     * @param json     vault JSON representation
     * @return a {@link Vault} instance in encrypted state
     * @throws GeneralSecurityException if the master password is wrong or
     *                                  cryptographic operations fail
     */
    public Vault fromJSON(
            @NotNull String json,
            @NotNull String masterPassword
    ) throws  GeneralSecurityException {
        JsonObject root = JsonParser.parseString(json).getAsJsonObject();
        JsonObject algorithm =  root.getAsJsonObject("algorithm");

        String salt = algorithm.get("salt").getAsString();
        String vaultKey = root.get("vaultKey").getAsString();
        String checker = root.get("checker").getAsString();

        VaultEncryptingStrategy strategy = new AESVaultEncryptingStrategy(
                masterPassword,
                salt,
                false
        );

        try {
            strategy.importVaultKey(vaultKey);
        } catch (AEADBadTagException e) {
            throw new WrongPasswordException("Decrypting Vault with wrong password attempt");
        }

        if (!checkMasterPassword(checker, strategy)) {
            throw new WrongPasswordException("Wrong master password");
        }

        Vault vault = new Vault(
                strategy,
                user,
                checker,
                true
        );

        // Parse Accounts
        if (root.has("accounts")) {
            JsonArray accounts = root.getAsJsonArray("accounts");
            for (JsonElement element : accounts) {
                JsonObject obj = element.getAsJsonObject();

                String id = obj.get("id").getAsString();
                String title = obj.get("title").getAsString();
                String username = obj.get("username").getAsString();
                String domain = obj.get("domain").getAsString();
                String password = obj.get("password").getAsString();
                boolean isEncrypted = !password.equals("***");

                vault.add(new Account(id, title, username, domain, password, isEncrypted));
            }
        }

        // Parse CreditCards
        if (root.has("creditcards")) {
            JsonArray creditCards = root.getAsJsonArray("creditcards");
            for (JsonElement element : creditCards) {
                JsonObject obj = element.getAsJsonObject();

                String id = obj.get("id").getAsString();
                String title = obj.get("title").getAsString();
                String cardHolderName = obj.get("cardHolderName").getAsString();
                String cardNumber = obj.get("cardNumber").getAsString();
                String expirationDate = obj.get("expirationDate").getAsString();
                String cvv = obj.get("cvv").getAsString();
                String postalCode = obj.get("postalCode").getAsString();
                boolean isEncrypted = !cvv.equals("***");

                vault.add(new CreditCard(
                        id, title, cardHolderName, cardNumber, expirationDate,
                        cvv, postalCode, isEncrypted
                ));
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

    /**
     * Compares two strings in (approximate) constant time to mitigate timing
     * attacks. Both strings must be non-null.
     */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        if (a.length() != b.length()) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
