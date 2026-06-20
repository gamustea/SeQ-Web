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
 * Represents a credit or debit card stored in the vault.
 */
@Getter
@Setter
public class CreditCard extends VaultObject {

    /**
     * Cardholder name printed on the card.
     */
    private String cardHolderName;

    /**
     * Card number (PAN). This is highly sensitive data.
     */
    private String cardNumber;

    /**
     * Expiration date in a human-readable format (e.g. "12/29").
     */
    private String expirationDate;

    /**
     * CVV/CVC code printed on the card. This is highly sensitive data.
     */
    private String cvv;

    /**
     * Billing ZIP/postal code.
     */
    private String postalCode;



    /**
     * Creates a new credit card.
     *
     * @param cardHolderName    name of the cardholder
     * @param cardNumber        card number (PAN)
     * @param expirationDate    expiration date (e.g. "12/29")
     * @param cvv               CVV/CVC code
     * @param postalCode        billing postal code
     * @param isEncrypted {@code true} if the fields being passed are already
     *                    encrypted (e.g., when loading from storage);
     *                    {@code false} if they are plain-text
     */
    public CreditCard(
            @NotNull String title,
            @NotNull String cardHolderName,
            @NotNull String cardNumber,
            @NotNull String expirationDate,
            @NotNull String cvv,
            @NotNull String postalCode,
            boolean isEncrypted
    ) {
        super("CDC", title, isEncrypted, true);

        this.cardHolderName = cardHolderName;
        this.cardNumber = cardNumber;
        this.expirationDate = expirationDate;
        this.cvv = cvv;
        this.postalCode = postalCode;
    }

    public CreditCard(
            @NotNull String id,
            @NotNull String title,
            @NotNull String cardHolderName,
            @NotNull String cardNumber,
            @NotNull String expirationDate,
            @NotNull String cvv,
            @NotNull String postalCode,
            boolean isEncrypted
    ) {
        super(id, title, isEncrypted, false);

        this.cardHolderName = cardHolderName;
        this.cardNumber = cardNumber;
        this.expirationDate = expirationDate;
        this.cvv = cvv;
        this.postalCode = postalCode;
    }

    public CreditCard(
            @NotNull String title,
            @NotNull String cardHolderName,
            @NotNull String cardNumber,
            @NotNull String expirationDate,
            @NotNull String cvv,
            @NotNull String postalCode,
            @NotNull Date createdAt,
            @NotNull Date updatedAt,
            boolean isEncrypted
    ) {
        super("CDC", title, isEncrypted, createdAt, updatedAt, true);

        this.cardHolderName = cardHolderName;
        this.cardNumber = cardNumber;
        this.expirationDate = expirationDate;
        this.cvv = cvv;
        this.postalCode = postalCode;
    }

    public CreditCard(
            @NotNull String id,
            @NotNull String title,
            @NotNull String cardHolderName,
            @NotNull String cardNumber,
            @NotNull String expirationDate,
            @NotNull String cvv,
            @NotNull String postalCode,
            @NotNull Date createdAt,
            @NotNull Date updatedAt,
            boolean isEncrypted
    ) {
        super(id, title, isEncrypted, createdAt, updatedAt, false);

        this.cardHolderName = cardHolderName;
        this.cardNumber = cardNumber;
        this.expirationDate = expirationDate;
        this.cvv = cvv;
        this.postalCode = postalCode;
    }


    @Override
    String transform(VaultEncryptingStrategy encryptor, boolean encrypt) {
        CreditCard oldCreditCard = (CreditCard) this.copy();
        super.transform(encryptor, encrypt);

        try {
            cardHolderName = encrypt
                    ? encryptor.encrypt(cardHolderName)
                    : encryptor.decrypt(cardHolderName);
            cardNumber = encrypt
                    ? encryptor.encrypt(cardNumber)
                    : encryptor.decrypt(cardNumber);

            expirationDate = encrypt
                    ? encryptor.encrypt(expirationDate)
                    : encryptor.decrypt(expirationDate);

            cvv = encrypt
                    ? encryptor.encrypt(cvv)
                    : encryptor.decrypt(cvv);

            postalCode = encrypt
                    ? encryptor.encrypt(postalCode)
                    : encryptor.decrypt(postalCode);

        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Error transforming credit card fields", e);
        }

        return oldCreditCard.toString();
    }

    @Override
    public boolean share(PublicKey publicKey, VaultEncryptingStrategy vaultEncryptingStrategy) {
        return false;
    }

    @Override
    public Storable copy() {
        return new CreditCard(
                this.getId(),
                title,
                cardHolderName,
                cardNumber,
                expirationDate,
                cvv,
                postalCode,
                getCreatedAt(),
                getUpdatedAt(),
                isEncrypted
        );
    }

    @Override
    public String toJson() {
        com.google.gson.JsonObject json = super.toJsonObject();

        String safeCardNumber = isEncrypted
                ? this.cardNumber
                : maskCardNumber(this.cardNumber);
        String safeCvv = isEncrypted ? this.cvv : "***";

        json.addProperty("cardHolderName", cardHolderName);
        json.addProperty("cardNumber", safeCardNumber);
        json.addProperty("expirationDate", expirationDate);
        json.addProperty("postalCode", postalCode);
        json.addProperty("cvv", safeCvv);

        return json.toString();
    }

    private static String maskCardNumber(String cardNumber) {
        if (cardNumber == null || cardNumber.length() < 4) {
            return "****";
        }
        return "****" + cardNumber.substring(cardNumber.length() - 4);
    }

    String toStorageJson() {
        com.google.gson.JsonObject json = super.toJsonObject();
        json.addProperty("cardHolderName", cardHolderName);
        json.addProperty("cardNumber", cardNumber);
        json.addProperty("expirationDate", expirationDate);
        json.addProperty("postalCode", postalCode);
        json.addProperty("cvv", cvv);
        return json.toString();
    }

    /**
     * Reconstruye un CreditCard a partir de su representación JSON devuelta por el Vault.
     */
    public static CreditCard fromJson(JsonObject json) {
        return new CreditCard(
                json.get("id").getAsString(),
                json.get("title").getAsString(),
                json.get("cardHolderName").getAsString(),
                json.get("cardNumber").getAsString(),
                json.get("expirationDate").getAsString(),
                json.get("cvv").getAsString(),
                json.get("postalCode").getAsString(),
                java.util.Date.from(java.time.Instant.parse(json.get("createdAt").getAsString())),
                java.util.Date.from(java.time.Instant.parse(json.get("updatedAt").getAsString())),
                true
        );
    }
}
