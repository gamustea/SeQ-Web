package com.seq.acheron.vault.storables;

import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;

import java.security.GeneralSecurityException;
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
            @NotNull String username,
            @NotNull String domain,
            @NotNull String password,
            boolean isEncrypted
    ) {
        super("ACC", isEncrypted);
        this.username = username;
        this.domain = domain;
        this.password = password;
    }

    public Account(
            @NotNull String username,
            @NotNull String domain,
            @NotNull String password,
            @NotNull Date createdAt,
            @NotNull Date updatedAt,
            boolean isEncrypted
    ) {
        super("ACC", isEncrypted, createdAt, updatedAt);
        this.username = username;
        this.domain = domain;
        this.password = password;
    }

    @Override
    String transform(VaultEncryptingStrategy encryptor, boolean encrypt) {
        Account oldAccount = (Account) copy();

        try {
            username = encrypt ?
                    encryptor.encrypt(username) :
                    encryptor.decrypt(username);
            domain = encrypt ?
                    encryptor.encrypt(domain)
                    : encryptor.decrypt(domain);
            password = encrypt ?
                    encryptor.encrypt(password) :
                    encryptor.decrypt(password);

            isEncrypted = encrypt;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Error transforming account fields", e);
        }

        return oldAccount.toString();
    }

    @Override
    public boolean share(PublicKey publicKey, VaultEncryptingStrategy vaultEncryptingStrategy) {
        return false;
    }

    @Override
    public VaultObject copy() {
        VaultObject.setObjectCounter(getObjectCounter() - 1);
        return new Account(
                username,
                domain,
                password,
                getCreatedAt(),
                getUpdatedAt(),
                isEncrypted
        );
    }

    @Override
    public String toJSON() {
        return "{" +
                super.toJSON() +
                "username:'" + username + "'," +
                "domain:'" + domain + "'," +
                '}';
    }
}
