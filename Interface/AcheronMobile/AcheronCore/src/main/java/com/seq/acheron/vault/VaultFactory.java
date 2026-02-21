package com.seq.acheron.vault;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.seq.acheron.agents.User;
import com.seq.acheron.secrets.symmetric.AESVaultEncryptingStrategy;
import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.storables.Account;
import com.seq.acheron.vault.storables.CreditCard;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;


public class VaultFactory {

    private static VaultFactory instance;
    private static final VaultEncryptingStrategy DEFAULT_STRATEGY;

    static {
        try {
            DEFAULT_STRATEGY = new AESVaultEncryptingStrategy(
                    "CONTRASEÑA",
                    "328197321098732190732198073291873219837281998321",
                    true
            );
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private final User user;

    private VaultFactory(User user) throws GeneralSecurityException {
        this.user = user;
    }

    public static VaultFactory getInstance(User user) throws GeneralSecurityException {
        if (instance == null) {
            instance = new VaultFactory(user);
        }
        return instance;
    }

    public static void resetInstance() {
        instance = null;
    }

    public Vault mockVault() throws GeneralSecurityException {
        return mockVault(user);
    }

    public Vault mockVault(User user) throws GeneralSecurityException {
        Vault vault = new Vault(DEFAULT_STRATEGY, user, false);

        // Accounts
        vault.add(new Account(
                "user@gmail.com",
                "mail.google.com",
                "P@ssw0rd123!",
                false
        ));

        vault.add(new Account(
                "gamustea",
                "github.com",
                "Gh1t#SecurePass",
                false
        ));

        vault.add(new Account(
                "user@gmail.com",
                "netflix.com",
                "N3tfl1x$Pass",
                false
        ));

        // Credit Cards
        vault.add(new CreditCard(
                "GABRIEL MUSTEATA",
                "4111111111111111",
                "12/27",
                "123",
                "28001",
                false
        ));

        vault.add(new CreditCard(
                "GABRIEL MUSTEATA",
                "5500005555555559",
                "08/26",
                "456",
                "28002",
                false
        ));

        return vault;
    }

    public Vault fromJSON(String json, VaultEncryptingStrategy strategy)
            throws GeneralSecurityException {

        JsonObject root = JsonParser.parseString(json).getAsJsonObject();

        String checker = root.get("checker").getAsString();
        String vaultKey = root.get("vaultKey").getAsString();

        strategy.importVaultKey(vaultKey);

        if (!checkMasterPassword(checker, strategy)) {
            throw new GeneralSecurityException("Wrong master password");
        }

        Vault vault = new Vault(
                strategy,
                user,
                checker,
                true
        );

        // Parsear Accounts
        if (root.has("accounts")) {
            JsonArray accounts = root.getAsJsonArray("accounts");
            for (JsonElement element : accounts) {
                JsonObject obj = element.getAsJsonObject();

                String id            = obj.get("id").getAsString();
                String username      = obj.get("username").getAsString();
                String domain        = obj.get("domain").getAsString();
                String password      = obj.get("password").getAsString();
                boolean isEncrypted  = !password.equals("***");

                vault.add(new Account(id, username, domain, password, isEncrypted));
            }
        }

        // Parsear CreditCards
        if (root.has("creditcards")) {
            JsonArray creditCards = root.getAsJsonArray("creditcards");
            for (JsonElement element : creditCards) {
                JsonObject obj = element.getAsJsonObject();

                String id            = obj.get("id").getAsString();
                String cardHolderName  = obj.get("cardHolderName").getAsString();
                String cardNumber      = obj.get("cardNumber").getAsString();
                String expirationDate  = obj.get("expirationDate").getAsString();
                String cvv             = obj.get("cvv").getAsString();
                String postalCode      = obj.get("postalCode").getAsString();
                boolean isEncrypted    = !cvv.equals("***");

                vault.add(new CreditCard(
                        id, cardHolderName, cardNumber, expirationDate,
                        cvv, postalCode, isEncrypted
                ));
            }
        }

        return vault;
    }

    private boolean checkMasterPassword(String checker, VaultEncryptingStrategy strategy) throws GeneralSecurityException {
        String decryptedChecker = strategy.decryptWithDerivedKey(checker);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(
                user.getUsername().getBytes(StandardCharsets.UTF_8)
        );
        StringBuilder hex = new StringBuilder();
        for (byte b : hashBytes) {
            hex.append(String.format("%02x", b));
        }

        return hex.toString().equals(decryptedChecker);
    }

}
