package com.seq.acheron.vault.storables;

import com.google.gson.JsonObject;
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.interfaces.Storable;
import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Date;

/**
 * Represents a bank account stored in the vault (IBAN, SWIFT/BIC and account
 * number). A staple structured type in managers such as 1Password and Dashlane.
 */
@Getter
@Setter
public class BankAccount extends VaultObject {

    private String bankName;
    private String holder;

    /**
     * International Bank Account Number. Considered sensitive.
     */
    private String iban;

    /**
     * SWIFT / BIC code. Considered sensitive.
     */
    private String swiftBic;

    /**
     * Local account number. Considered sensitive.
     */
    private String accountNumber;

    public BankAccount(
            @NotNull String title,
            @NotNull String bankName,
            @NotNull String holder,
            @NotNull String iban,
            @NotNull String swiftBic,
            @NotNull String accountNumber,
            boolean isEncrypted
    ) {
        super("BNK", title, isEncrypted, true);
        this.bankName = bankName;
        this.holder = holder;
        this.iban = iban;
        this.swiftBic = swiftBic;
        this.accountNumber = accountNumber;
    }

    public BankAccount(
            @NotNull String id,
            @NotNull String title,
            @NotNull String bankName,
            @NotNull String holder,
            @NotNull String iban,
            @NotNull String swiftBic,
            @NotNull String accountNumber,
            @NotNull Date createdAt,
            @NotNull Date updatedAt,
            boolean isEncrypted
    ) {
        super(id, title, isEncrypted, createdAt, updatedAt, false);
        this.bankName = bankName;
        this.holder = holder;
        this.iban = iban;
        this.swiftBic = swiftBic;
        this.accountNumber = accountNumber;
    }

    @Override
    String transform(VaultEncryptingStrategy encryptor, boolean encrypt) {
        BankAccount old = (BankAccount) copy();
        super.transform(encryptor, encrypt);

        try {
            bankName      = encrypt ? encryptor.encrypt(bankName)      : encryptor.decrypt(bankName);
            holder        = encrypt ? encryptor.encrypt(holder)        : encryptor.decrypt(holder);
            iban          = encrypt ? encryptor.encrypt(iban)          : encryptor.decrypt(iban);
            swiftBic      = encrypt ? encryptor.encrypt(swiftBic)      : encryptor.decrypt(swiftBic);
            accountNumber = encrypt ? encryptor.encrypt(accountNumber) : encryptor.decrypt(accountNumber);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Error transforming bank account fields", e);
        }

        return old.toString();
    }

    @Override
    public boolean share(PublicKey publicKey, VaultEncryptingStrategy vaultEncryptingStrategy) {
        return false;
    }

    @Override
    public String category() {
        return "bankaccounts";
    }

    @Override
    public Storable copy() {
        return new BankAccount(
                this.getId(),
                title,
                bankName,
                holder,
                iban,
                swiftBic,
                accountNumber,
                getCreatedAt(),
                getUpdatedAt(),
                isEncrypted
        );
    }

    @Override
    public String toJson() {
        JsonObject json = super.toJsonObject();
        json.addProperty("bankName", bankName);
        json.addProperty("holder", holder);
        json.addProperty("iban", isEncrypted ? iban : maskTail(iban));
        json.addProperty("swiftBic", isEncrypted ? swiftBic : "***");
        json.addProperty("accountNumber", isEncrypted ? accountNumber : maskTail(accountNumber));
        return json.toString();
    }

    private static String maskTail(String value) {
        if (value == null || value.length() < 4) {
            return "****";
        }
        return "****" + value.substring(value.length() - 4);
    }

    /**
     * Reconstruye un BankAccount a partir de su representación JSON devuelta por el Vault.
     */
    public static BankAccount fromJson(JsonObject json) {
        return new BankAccount(
                json.get("id").getAsString(),
                json.get("title").getAsString(),
                json.get("bankName").getAsString(),
                json.get("holder").getAsString(),
                json.get("iban").getAsString(),
                json.get("swiftBic").getAsString(),
                json.get("accountNumber").getAsString(),
                java.util.Date.from(java.time.Instant.parse(json.get("createdAt").getAsString())),
                java.util.Date.from(java.time.Instant.parse(json.get("updatedAt").getAsString())),
                true
        );
    }
}
