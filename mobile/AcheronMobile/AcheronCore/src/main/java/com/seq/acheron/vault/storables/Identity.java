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
 * Represents a personal identity stored in the vault, intended for autofill of
 * personal data (name, contact details, postal address and an identity
 * document number). Mirrors the "Identity" entry common to most password
 * managers.
 */
@Getter
@Setter
public class Identity extends VaultObject {

    private String fullName;
    private String email;
    private String phone;
    private String address;
    private String city;
    private String country;

    /**
     * National ID / passport / document number. Considered sensitive.
     */
    private String documentId;

    public Identity(
            @NotNull String title,
            @NotNull String fullName,
            @NotNull String email,
            @NotNull String phone,
            @NotNull String address,
            @NotNull String city,
            @NotNull String country,
            @NotNull String documentId,
            boolean isEncrypted
    ) {
        super("IDN", title, isEncrypted, true);
        this.fullName = fullName;
        this.email = email;
        this.phone = phone;
        this.address = address;
        this.city = city;
        this.country = country;
        this.documentId = documentId;
    }

    public Identity(
            @NotNull String id,
            @NotNull String title,
            @NotNull String fullName,
            @NotNull String email,
            @NotNull String phone,
            @NotNull String address,
            @NotNull String city,
            @NotNull String country,
            @NotNull String documentId,
            @NotNull Date createdAt,
            @NotNull Date updatedAt,
            boolean isEncrypted
    ) {
        super(id, title, isEncrypted, createdAt, updatedAt, false);
        this.fullName = fullName;
        this.email = email;
        this.phone = phone;
        this.address = address;
        this.city = city;
        this.country = country;
        this.documentId = documentId;
    }

    @Override
    String transform(VaultEncryptingStrategy encryptor, boolean encrypt) {
        Identity old = (Identity) copy();
        super.transform(encryptor, encrypt);

        try {
            fullName   = encrypt ? encryptor.encrypt(fullName)   : encryptor.decrypt(fullName);
            email      = encrypt ? encryptor.encrypt(email)      : encryptor.decrypt(email);
            phone      = encrypt ? encryptor.encrypt(phone)      : encryptor.decrypt(phone);
            address    = encrypt ? encryptor.encrypt(address)    : encryptor.decrypt(address);
            city       = encrypt ? encryptor.encrypt(city)       : encryptor.decrypt(city);
            country    = encrypt ? encryptor.encrypt(country)    : encryptor.decrypt(country);
            documentId = encrypt ? encryptor.encrypt(documentId) : encryptor.decrypt(documentId);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Error transforming identity fields", e);
        }

        return old.toString();
    }

    @Override
    public boolean share(PublicKey publicKey, VaultEncryptingStrategy vaultEncryptingStrategy) {
        return false;
    }

    @Override
    public String category() {
        return "identities";
    }

    @Override
    public Storable copy() {
        return new Identity(
                this.getId(),
                title,
                fullName,
                email,
                phone,
                address,
                city,
                country,
                documentId,
                getCreatedAt(),
                getUpdatedAt(),
                isEncrypted
        );
    }

    @Override
    public String toJson() {
        JsonObject json = super.toJsonObject();
        json.addProperty("fullName", fullName);
        json.addProperty("email", email);
        json.addProperty("phone", phone);
        json.addProperty("address", address);
        json.addProperty("city", city);
        json.addProperty("country", country);
        json.addProperty("documentId", isEncrypted ? documentId : "***");
        return json.toString();
    }

    /**
     * Reconstruye una Identity a partir de su representación JSON devuelta por el Vault.
     */
    public static Identity fromJson(JsonObject json) {
        return new Identity(
                json.get("id").getAsString(),
                json.get("title").getAsString(),
                json.get("fullName").getAsString(),
                json.get("email").getAsString(),
                json.get("phone").getAsString(),
                json.get("address").getAsString(),
                json.get("city").getAsString(),
                json.get("country").getAsString(),
                json.get("documentId").getAsString(),
                java.util.Date.from(java.time.Instant.parse(json.get("createdAt").getAsString())),
                java.util.Date.from(java.time.Instant.parse(json.get("updatedAt").getAsString())),
                true
        );
    }
}
