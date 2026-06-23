package com.seq.acheron.vault;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.seq.acheron.exceptions.AcheronException;
import com.seq.acheron.exceptions.WrongPasswordException;
import com.seq.acheron.vault.secrets.symmetric.Argon2VaultEncryptingStrategy;
import com.seq.acheron.vault.secrets.symmetric.PBKDF2VaultEncryptingStrategy;

import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.util.CryptoUtils;
import com.seq.acheron.util.Pair;
import com.seq.acheron.vault.storables.Account;
import com.seq.acheron.vault.storables.BankAccount;
import com.seq.acheron.vault.storables.CreditCard;
import com.seq.acheron.vault.storables.Identity;
import com.seq.acheron.vault.storables.SecureNote;
import com.seq.acheron.vault.storables.SoftwareLicense;
import com.seq.acheron.vault.storables.WifiNetwork;
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

    private static final String MOCK_VAULT_PASSWD = "Contrase\u00f1a";

    public VaultFactory(User user) {
        this.user = Objects.requireNonNull(user, "user must not be null");
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

        // Secure note (demo data only)
        vault.add(new SecureNote(
                "Recovery codes",
                "8F3K-2L9P-77QX\n1A2B-3C4D-5E6F",
                false
        ));

        // Identity (demo data only)
        vault.add(new Identity(
                "Personal ID",
                "Gabriel Musteata",
                "gabriel@example.com",
                "+34 600 000 000",
                "Calle Falsa 123",
                "Madrid",
                "España",
                "12345678Z",
                false
        ));

        // Bank account (demo data only)
        vault.add(new BankAccount(
                "Main Bank",
                "Banco Ejemplo",
                "GABRIEL MUSTEATA",
                "ES9121000418450200051332",
                "CAIXESBBXXX",
                "0200051332",
                false
        ));

        // Wi-Fi network (demo data only)
        vault.add(new WifiNetwork(
                "Home Wi-Fi",
                "ACHERON_5G",
                "sup3r-s3cret-wifi",
                "WPA3",
                false
        ));

        // Software license (demo data only)
        vault.add(new SoftwareLicense(
                "IntelliJ IDEA",
                "IntelliJ IDEA Ultimate",
                "AB12C-DE34F-GH56I-JK78L",
                "Gabriel Musteata",
                "2026.1",
                false
        ));

        return vault;
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
     *   <li>{@code "accounts"} — optional array of Account objects</li>
     *   <li>{@code "creditcards"} — optional array of CreditCard objects</li>
     *   <li>{@code "securenotes"} — optional array of SecureNote objects</li>
     *   <li>{@code "identities"} — optional array of Identity objects</li>
     *   <li>{@code "bankaccounts"} — optional array of BankAccount objects</li>
     *   <li>{@code "wifinetworks"} — optional array of WifiNetwork objects</li>
     *   <li>{@code "licenses"} — optional array of SoftwareLicense objects</li>
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

        if (root.has("securenotes")) {
            for (JsonElement element : root.getAsJsonArray("securenotes")) {
                vault.add(SecureNote.fromJson(element.getAsJsonObject()));
            }
        }

        if (root.has("identities")) {
            for (JsonElement element : root.getAsJsonArray("identities")) {
                vault.add(Identity.fromJson(element.getAsJsonObject()));
            }
        }

        if (root.has("bankaccounts")) {
            for (JsonElement element : root.getAsJsonArray("bankaccounts")) {
                vault.add(BankAccount.fromJson(element.getAsJsonObject()));
            }
        }

        if (root.has("wifinetworks")) {
            for (JsonElement element : root.getAsJsonArray("wifinetworks")) {
                vault.add(WifiNetwork.fromJson(element.getAsJsonObject()));
            }
        }

        if (root.has("licenses")) {
            for (JsonElement element : root.getAsJsonArray("licenses")) {
                vault.add(SoftwareLicense.fromJson(element.getAsJsonObject()));
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
        String decryptedChecker;
        try {
            decryptedChecker = strategy.decryptWithDerivedKey(checker);
        } catch (AEADBadTagException e) {
            // Clave maestra incorrecta: no es un error criptografico generico.
            return false;
        }

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
            @NotNull String salt,
            int iterations,
            int memoryKiB,
            int parallelism
    ) throws GeneralSecurityException {
        if ("PBKDF2".equalsIgnoreCase(kdfId)) {
            return new PBKDF2VaultEncryptingStrategy(masterPassword, salt, (SecretKey) null,
                    iterations, 256);
        }
        return new Argon2VaultEncryptingStrategy(masterPassword, salt, (SecretKey) null,
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
