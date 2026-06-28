package com.seq.acheron;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import com.seq.acheron.util.CryptoUtils;
import com.seq.acheron.vault.User;
import com.seq.acheron.vault.Vault;
import com.seq.acheron.vault.secrets.symmetric.Argon2VaultEncryptingStrategy;
import com.seq.acheron.vault.secrets.symmetric.PBKDF2VaultEncryptingStrategy;
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.storables.Account;
import com.seq.acheron.vault.storables.CreditCard;
import com.seq.acheron.vault.storables.SecureNote;

import org.junit.jupiter.api.Test;

import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Date;

/**
 * Generates the SHARED TEST VECTORS between AcheronCore (Java) and the web
 * client (JS). It is the source of truth for interoperability: AcheronCore
 * encrypts a few vaults with known master password and salt and dumps their
 * JSON (in the same format returned by {@code GET /vault}) together with the
 * expected plain-text values. The JS test (web/app/test/acheron.interop.test.mjs)
 * opens those vaults and checks that it decrypts exactly what is expected.
 *
 * This is not an assertion test: it is a generator. Run it on purpose with:
 *
 *   mvn -q -Dtest=VectorGenerator -DfailIfNoTests=false \
 *       -Dvectors.out=&lt;repo&gt;/tests/acheron-vectors.json test
 *
 * Default output: target/acheron-vectors.json (if vectors.out is not provided).
 */
public class VectorGenerator {

    /** Fixed createdAt/updatedAt so the output is deterministic. */
    private static final Date FIXED_DATE = Date.from(Instant.parse("2026-01-01T00:00:00Z"));

    @Test
    void generate() throws Exception {
        JsonArray cases = new JsonArray();
        cases.add(buildCase("Argon2"));
        cases.add(buildCase("PBKDF2"));

        JsonObject root = new JsonObject();
        root.add("cases", cases);

        String out = System.getProperty("vectors.out", "target/acheron-vectors.json");
        Path path = Paths.get(out).toAbsolutePath();
        Files.createDirectories(path.getParent());

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (Writer w = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            gson.toJson(root, w);
        }
        System.out.println("[VectorGenerator] vectors written to " + path);
    }

    private JsonObject buildCase(String kdf) throws Exception {
        String masterPassword = "Master-" + kdf + "-123!";
        String username = "alice";
        String salt = CryptoUtils.generateSalt(); // 16 bytes, Base64

        User user = new User("U1", "Alice", "Doe", "alice@example.com", username);

        VaultEncryptingStrategy strategy = "PBKDF2".equalsIgnoreCase(kdf)
                ? new PBKDF2VaultEncryptingStrategy(masterPassword, salt, true)
                : new Argon2VaultEncryptingStrategy(masterPassword, salt, true);

        Vault vault = new Vault(strategy, user, false);

        // ── plain-text storables (explicit ids so they stay stable) ──
        Account account = new Account(
                "ACC0", "Gmail", "alice@gmail.com", "mail.google.com",
                "P@ssw0rd-acc-0", FIXED_DATE, FIXED_DATE, false);
        CreditCard card = new CreditCard(
                "CDC0", "Personal Card", "ALICE DOE", "4111111111111111",
                "12/29", "123", "28001", FIXED_DATE, FIXED_DATE, false);
        SecureNote note = new SecureNote(
                "SCN0", "Recovery codes", "8F3K-2L9P-77QX\n1A2B-3C4D-5E6F",
                FIXED_DATE, FIXED_DATE, false);

        vault.add(account).add(card).add(note);

        // ── what the web client must obtain after decryption ──
        JsonObject expected = new JsonObject();
        expected.add("ACC0", obj(
                "title", "Gmail",
                "username", "alice@gmail.com",
                "domain", "mail.google.com",
                "password", "P@ssw0rd-acc-0"));
        expected.add("CDC0", obj(
                "title", "Personal Card",
                "cardHolderName", "ALICE DOE",
                "cardNumber", "4111111111111111",
                "expirationDate", "12/29",
                "postalCode", "28001",
                "cvv", "123"));
        expected.add("SCN0", obj(
                "title", "Recovery codes",
                "content", "8F3K-2L9P-77QX\n1A2B-3C4D-5E6F"));

        // ── encrypt and serialise just as the vault would persist ──
        vault.encryptAll();
        JsonObject vaultJson = JsonParser.parseString(vault.toJson()).getAsJsonObject();

        JsonObject c = new JsonObject();
        c.addProperty("kdf", kdf);
        c.addProperty("masterPassword", masterPassword);
        c.addProperty("username", username);
        c.add("vault", vaultJson);
        c.add("expected", expected);
        return c;
    }

    /** Builds a JsonObject from key/value pairs. */
    private static JsonObject obj(String... kv) {
        JsonObject o = new JsonObject();
        for (int i = 0; i < kv.length; i += 2) {
            o.addProperty(kv[i], kv[i + 1]);
        }
        return o;
    }
}
