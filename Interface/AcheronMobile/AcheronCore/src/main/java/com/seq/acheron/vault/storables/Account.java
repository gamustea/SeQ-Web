package com.seq.acheron.vault.storables;

import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import lombok.Getter;
import lombok.Setter;

/**
 * Represents a user account stored in the vault,
 * for example an account for a given domain or service.
 */
@Getter
@Setter
public class Account implements Storable {

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
     * Creates a new account with plain-text data.
     *
     * @param username the username (login)
     * @param domain   the domain or service
     * @param password the account password in plain text
     */
    public Account(String username, String domain, String password) {
        this.username = username;
        this.domain = domain;
        this.password = password;
    }

    @Override
    public String encrypt(VaultEncryptingStrategy encryptor) {
        return "";
    }

    @Override
    public String decrypt(VaultEncryptingStrategy encryptor) {
        return "";
    }

    @Override
    public String toString() {
        return "Account{" +
                "username='" + username + '\'' +
                ", domain='" + domain + '\'' +
                '}';
    }
}
