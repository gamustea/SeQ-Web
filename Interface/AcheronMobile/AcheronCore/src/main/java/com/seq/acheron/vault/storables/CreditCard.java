package com.seq.acheron.vault.storables;

import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import lombok.Getter;
import lombok.Setter;

/**
 * Represents a credit or debit card stored in the vault.
 */
@Getter
@Setter
public class CreditCard implements Storable {

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
    private Integer postalCode;

    /**
     * Creates a new credit card with plain-text data.
     *
     * @param cardHolderName name of the card holder
     * @param cardNumber     card number (PAN)
     * @param expirationDate expiration date (e.g. "12/29")
     * @param cvv            CVV/CVC code
     * @param postalCode     billing postal code
     * @param password       extra secret (e.g. PIN) in plain text
     */
    public CreditCard(
            String cardHolderName,
            String cardNumber,
            String expirationDate,
            String cvv,
            Integer postalCode,
            String password) {

        this.cardHolderName = cardHolderName;
        this.cardNumber = cardNumber;
        this.expirationDate = expirationDate;
        this.cvv = cvv;
        this.postalCode = postalCode;
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
