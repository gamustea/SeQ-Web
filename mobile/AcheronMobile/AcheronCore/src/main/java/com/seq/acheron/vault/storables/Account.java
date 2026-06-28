package com.seq.acheron.vault.storables;

import com.google.gson.JsonObject;
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.interfaces.Storable;
import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;

import java.security.PublicKey;
import java.util.Date;

/**
 * Represents a user account stored in the vault,
 * for example an account for a given domain or service.
 */
@Getter
@Setter
public class Account extends VaultObject {

    /**
     * Persistence category (JSON array key) for this type. See {@code StorableTypes}.
     */
    public static final String CATEGORY = "accounts";

    /**
     * Username used to log in.
     */
    private String username;

    /**
     * Domain or service this account belongs to
     * (e.g. "github.com", "mail.example.com").
     */
    private String domain;

    /**
     * Password associated with this account.
     * <p>
     * This value may be plain text or encrypted (for example,
     * Base64-encoded bytes of "IV || ciphertext"), depending on
     * whether {@link #encrypt(VaultEncryptingStrategy)} has been called.
     */
    private String password;

    /**
     * Creates a new account.
     *
     * @param username the username (login)
     * @param domain   the domain or service
     * @param password the account password in plain text
     * @param isEncrypted {@code true} if the fields being passed are already
     *                    encrypted (e.g., when loading from storage);
     *                    {@code false} if they are plain-text
     */
    public Account(
            @NotNull String title,
            @NotNull String username,
            @NotNull String domain,
            @NotNull String password,
            boolean isEncrypted
    ) {
        super("ACC", title, isEncrypted, true);
        this.username = username;
        this.domain = domain;
        this.password = password;
    }

    public Account(
            @NotNull String id,
            @NotNull String title,
            @NotNull String username,
            @NotNull String domain,
            @NotNull String password,
            boolean isEncrypted
    ) {
        super(id, title, isEncrypted, false);
        this.username = username;
        this.domain = domain;
        this.password = password;
    }

    public Account(
            @NotNull String id,
            @NotNull String title,
            @NotNull String username,
            @NotNull String domain,
            @NotNull String password,
            @NotNull Date createdAt,
            @NotNull Date updatedAt,
            boolean isEncrypted
    ) {
        super(id, title, isEncrypted, createdAt, updatedAt, false);
        this.username = username;
        this.domain = domain;
        this.password = password;
    }

    @Override
    String transform(VaultEncryptingStrategy encryptor, boolean encrypt) {
        String snapshot = toString();
        super.transform(encryptor, encrypt);
        username = apply(encryptor, encrypt, username);
        domain   = apply(encryptor, encrypt, domain);
        password = apply(encryptor, encrypt, password);
        return snapshot;
    }

    @Override
    public boolean share(PublicKey publicKey, VaultEncryptingStrategy vaultEncryptingStrategy) {
        return false;
    }

    @Override
    public String category() {
        return CATEGORY;
    }

    @Override
    public Storable copy() {
        return new Account(
                this.getId(),
                title,
                username,
                domain,
                password,
                getCreatedAt(),
                getUpdatedAt(),
                isEncrypted
        );
    }

    @Override
    public String toJson() {
        com.google.gson.JsonObject json = super.toJsonObject();

        String safePassword = revealOrMask(password, "***");
        json.addProperty("username", username);
        json.addProperty("domain", domain);
        json.addProperty("password", safePassword);

        return json.toString();
    }

    /**
     * Reconstructs an Account from the JSON representation returned by the Vault.
     */
    public static Account fromJson(JsonObject json) {
        return new Account(
                json.get("id").getAsString(),
                json.get("title").getAsString(),
                json.get("username").getAsString(),
                json.get("domain").getAsString(),
                json.get("password").getAsString(),
                // Assumes the standard ISO-8601 format written by DateTimeFormatter
                java.util.Date.from(java.time.Instant.parse(json.get("createdAt").getAsString())),
                java.util.Date.from(java.time.Instant.parse(json.get("updatedAt").getAsString())),
                true
        );
    }
}
