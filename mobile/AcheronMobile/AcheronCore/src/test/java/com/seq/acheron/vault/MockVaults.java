package com.seq.acheron.vault;

import com.seq.acheron.util.CryptoUtils;
import com.seq.acheron.vault.secrets.symmetric.PBKDF2VaultEncryptingStrategy;
import com.seq.acheron.vault.storables.Account;
import com.seq.acheron.vault.storables.BankAccount;
import com.seq.acheron.vault.storables.CreditCard;
import com.seq.acheron.vault.storables.Identity;
import com.seq.acheron.vault.storables.SecureNote;
import com.seq.acheron.vault.storables.SoftwareLicense;
import com.seq.acheron.vault.storables.WifiNetwork;

import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * Test fixture that builds an in-memory {@link Vault} populated with demo
 * credentials, one of each storable type.
 * <p>
 * It lives in the test source set on purpose: the demo secrets must never be
 * compiled into the production AcheronCore artifact.
 */
public final class MockVaults {

    /** Master password used by {@link #create(User)}. */
    public static final String PASSWORD = "Contraseña";

    private MockVaults() {}

    /**
     * Builds an unencrypted demo vault owned by {@code user}, containing one
     * item of each storable type. Intended for tests and UI prototyping only.
     *
     * @param user logical owner for the returned vault
     * @return a demo {@link Vault} instance (not encrypted)
     */
    public static Vault create(User user) throws GeneralSecurityException {
        Objects.requireNonNull(user, "user must not be null");

        Vault vault = new Vault(
                new PBKDF2VaultEncryptingStrategy(PASSWORD, CryptoUtils.generateSalt(), true),
                user,
                false
        );

        vault.add(new Account("Gmail Account", "user@gmail.com", "mail.google.com", "P@ssw0rd123!", false));
        vault.add(new Account("Github Account", "gamustea", "github.com", "Gh1t#SecurePass", false));
        vault.add(new Account("Netflix Account", "user@gmail.com", "netflix.com", "N3tfl1x$Pass", false));

        vault.add(new CreditCard("Personal Card", "GABRIEL MUSTEATA", "4111111111111111", "12/27", "123", "28001", false));
        vault.add(new CreditCard("Auxiliary Card", "GABRIEL MUSTEATA", "5500005555555559", "08/26", "456", "28002", false));

        vault.add(new SecureNote("Recovery codes", "8F3K-2L9P-77QX\n1A2B-3C4D-5E6F", false));

        vault.add(new Identity("Personal ID", "Gabriel Musteata", "gabriel@example.com", "+34 600 000 000",
                "Calle Falsa 123", "Madrid", "España", "12345678Z", false));

        vault.add(new BankAccount("Main Bank", "Banco Ejemplo", "GABRIEL MUSTEATA",
                "ES9121000418450200051332", "CAIXESBBXXX", "0200051332", false));

        vault.add(new WifiNetwork("Home Wi-Fi", "ACHERON_5G", "sup3r-s3cret-wifi", "WPA3", false));

        vault.add(new SoftwareLicense("IntelliJ IDEA", "IntelliJ IDEA Ultimate",
                "AB12C-DE34F-GH56I-JK78L", "Gabriel Musteata", "2026.1", false));

        return vault;
    }
}
