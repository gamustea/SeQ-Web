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
 * Genera los VECTORES DE PRUEBA COMPARTIDOS entre AcheronCore (Java) y el
 * cliente web (JS). Es la fuente de verdad de la interoperabilidad: AcheronCore
 * cifra unos vaults con master password y salt conocidos y vuelca su JSON (en
 * el mismo formato que devuelve {@code GET /vault}) junto con los valores en
 * texto plano esperados. El test JS (web/app/test/acheron.interop.test.mjs)
 * abre esos vaults y comprueba que descifra exactamente lo esperado.
 *
 * No es un test de aserción: es un generador. Se ejecuta a propósito con:
 *
 *   mvn -q -Dtest=VectorGenerator -DfailIfNoTests=false \
 *       -Dvectors.out=&lt;repo&gt;/tests/acheron-vectors.json test
 *
 * Salida por defecto: target/acheron-vectors.json (si no se pasa vectors.out).
 */
public class VectorGenerator {

    /** createdAt/updatedAt fijos para que la salida sea determinista. */
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
        System.out.println("[VectorGenerator] vectores escritos en " + path);
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

        // ── storables en texto plano (ids explícitos para que sean estables) ──
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

        // ── lo que el cliente web debe obtener al descifrar ──
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

        // ── cifrar y serializar igual que persistiría el vault ──
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

    /** Construye un JsonObject a partir de pares clave/valor. */
    private static JsonObject obj(String... kv) {
        JsonObject o = new JsonObject();
        for (int i = 0; i < kv.length; i += 2) {
            o.addProperty(kv[i], kv[i + 1]);
        }
        return o;
    }
}
