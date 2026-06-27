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
 * Represents the credentials for a Wi-Fi network (SSID, passphrase and the
 * security scheme). A common convenience entry in 1Password and Bitwarden.
 */
@Getter
@Setter
public class WifiNetwork extends VaultObject {

    /**
     * Network name (SSID).
     */
    private String ssid;

    /**
     * Network passphrase. Considered sensitive.
     */
    private String password;

    /**
     * Security scheme, e.g. "WPA2", "WPA3", "WEP", "Open".
     */
    private String securityType;

    public WifiNetwork(
            @NotNull String title,
            @NotNull String ssid,
            @NotNull String password,
            @NotNull String securityType,
            boolean isEncrypted
    ) {
        super("WIF", title, isEncrypted, true);
        this.ssid = ssid;
        this.password = password;
        this.securityType = securityType;
    }

    public WifiNetwork(
            @NotNull String id,
            @NotNull String title,
            @NotNull String ssid,
            @NotNull String password,
            @NotNull String securityType,
            @NotNull Date createdAt,
            @NotNull Date updatedAt,
            boolean isEncrypted
    ) {
        super(id, title, isEncrypted, createdAt, updatedAt, false);
        this.ssid = ssid;
        this.password = password;
        this.securityType = securityType;
    }

    @Override
    String transform(VaultEncryptingStrategy encryptor, boolean encrypt) {
        WifiNetwork old = (WifiNetwork) copy();
        super.transform(encryptor, encrypt);

        try {
            ssid         = encrypt ? encryptor.encrypt(ssid)         : encryptor.decrypt(ssid);
            password     = encrypt ? encryptor.encrypt(password)     : encryptor.decrypt(password);
            securityType = encrypt ? encryptor.encrypt(securityType) : encryptor.decrypt(securityType);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Error transforming wifi network fields", e);
        }

        return old.toString();
    }

    @Override
    public boolean share(PublicKey publicKey, VaultEncryptingStrategy vaultEncryptingStrategy) {
        return false;
    }

    @Override
    public String category() {
        return "wifinetworks";
    }

    @Override
    public Storable copy() {
        return new WifiNetwork(
                this.getId(),
                title,
                ssid,
                password,
                securityType,
                getCreatedAt(),
                getUpdatedAt(),
                isEncrypted
        );
    }

    @Override
    public String toJson() {
        JsonObject json = super.toJsonObject();
        json.addProperty("ssid", ssid);
        json.addProperty("password", isEncrypted ? password : "***");
        json.addProperty("securityType", securityType);
        return json.toString();
    }

    /**
     * Reconstruye un WifiNetwork a partir de su representación JSON devuelta por el Vault.
     */
    public static WifiNetwork fromJson(JsonObject json) {
        return new WifiNetwork(
                json.get("id").getAsString(),
                json.get("title").getAsString(),
                json.get("ssid").getAsString(),
                json.get("password").getAsString(),
                json.get("securityType").getAsString(),
                java.util.Date.from(java.time.Instant.parse(json.get("createdAt").getAsString())),
                java.util.Date.from(java.time.Instant.parse(json.get("updatedAt").getAsString())),
                true
        );
    }
}
