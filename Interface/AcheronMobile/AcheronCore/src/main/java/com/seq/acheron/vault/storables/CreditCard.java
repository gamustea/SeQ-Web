package com.seq.acheron.vault.storables;

import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

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
            @NotNull String cardHolderName,
            @NotNull String cardNumber,
            @NotNull String expirationDate,
            @NotNull String cvv,
            @NotNull String postalCode,
            boolean isEncrypted
    ) {
        super("CDC", isEncrypted);

        this.cardHolderName = cardHolderName;
        this.cardNumber = cardNumber;
        this.expirationDate = expirationDate;
        this.cvv = cvv;
        this.postalCode = postalCode;
    }


    @Override
    public String transform(VaultEncryptingStrategy encryptor, boolean encrypt) {
        CreditCard oldCreditCard = (CreditCard) this.copy();

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

            isEncrypted = encrypt;
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
    public VaultObject copy() {
        return new CreditCard(
                cardHolderName,
                cardNumber,
                expirationDate,
                cvv,
                postalCode,
                isEncrypted
        );
    }

    @Override
    public String toString() {
        return "CreditCard{" +
                "cardHolderName='" + cardHolderName + '\'' +
                // Never log full card number or CVV:
                ", cardNumber='****" + (cardNumber != null && cardNumber.length() >= 4
                ? cardNumber.substring(cardNumber.length() - 4) : "") + '\'' +
                ", expirationDate='" + expirationDate + '\'' +
                ", postalCode=" + postalCode +
                '}';
    }
}
