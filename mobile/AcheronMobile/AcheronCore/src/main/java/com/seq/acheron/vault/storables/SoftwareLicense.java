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
 * Represents a software license / product key stored in the vault
 * (product name, license key, licensee and version). A long-standing entry
 * type in 1Password ("Software License").
 */
@Getter
@Setter
public class SoftwareLicense extends VaultObject {

    private String product;

    /**
     * The product / activation key. Considered sensitive.
     */
    private String licenseKey;

    private String licensedTo;
    private String version;

    public SoftwareLicense(
            @NotNull String title,
            @NotNull String product,
            @NotNull String licenseKey,
            @NotNull String licensedTo,
            @NotNull String version,
            boolean isEncrypted
    ) {
        super("LIC", title, isEncrypted, true);
        this.product = product;
        this.licenseKey = licenseKey;
        this.licensedTo = licensedTo;
        this.version = version;
    }

    public SoftwareLicense(
            @NotNull String id,
            @NotNull String title,
            @NotNull String product,
            @NotNull String licenseKey,
            @NotNull String licensedTo,
            @NotNull String version,
            @NotNull Date createdAt,
            @NotNull Date updatedAt,
            boolean isEncrypted
    ) {
        super(id, title, isEncrypted, createdAt, updatedAt, false);
        this.product = product;
        this.licenseKey = licenseKey;
        this.licensedTo = licensedTo;
        this.version = version;
    }

    @Override
    String transform(VaultEncryptingStrategy encryptor, boolean encrypt) {
        SoftwareLicense old = (SoftwareLicense) copy();
        super.transform(encryptor, encrypt);

        try {
            product    = encrypt ? encryptor.encrypt(product)    : encryptor.decrypt(product);
            licenseKey = encrypt ? encryptor.encrypt(licenseKey) : encryptor.decrypt(licenseKey);
            licensedTo = encrypt ? encryptor.encrypt(licensedTo) : encryptor.decrypt(licensedTo);
            version    = encrypt ? encryptor.encrypt(version)    : encryptor.decrypt(version);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Error transforming software license fields", e);
        }

        return old.toString();
    }

    @Override
    public boolean share(PublicKey publicKey, VaultEncryptingStrategy vaultEncryptingStrategy) {
        return false;
    }

    @Override
    public String category() {
        return "licenses";
    }

    @Override
    public Storable copy() {
        return new SoftwareLicense(
                this.getId(),
                title,
                product,
                licenseKey,
                licensedTo,
                version,
                getCreatedAt(),
                getUpdatedAt(),
                isEncrypted
        );
    }

    @Override
    public String toJson() {
        JsonObject json = super.toJsonObject();
        json.addProperty("product", product);
        json.addProperty("licenseKey", isEncrypted ? licenseKey : "***");
        json.addProperty("licensedTo", licensedTo);
        json.addProperty("version", version);
        return json.toString();
    }

    /**
     * Reconstruye una SoftwareLicense a partir de su representación JSON devuelta por el Vault.
     */
    public static SoftwareLicense fromJson(JsonObject json) {
        return new SoftwareLicense(
                json.get("id").getAsString(),
                json.get("title").getAsString(),
                json.get("product").getAsString(),
                json.get("licenseKey").getAsString(),
                json.get("licensedTo").getAsString(),
                json.get("version").getAsString(),
                java.util.Date.from(java.time.Instant.parse(json.get("createdAt").getAsString())),
                java.util.Date.from(java.time.Instant.parse(json.get("updatedAt").getAsString())),
                true
        );
    }
}
