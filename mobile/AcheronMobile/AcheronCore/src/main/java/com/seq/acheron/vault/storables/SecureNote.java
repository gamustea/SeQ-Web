package com.seq.acheron.vault.storables;

import com.google.gson.JsonObject;
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.interfaces.Storable;
import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;

import java.security.PublicKey;
import java.util.Date;

/**
 * Represents a free-form encrypted note stored in the vault.
 * <p>
 * This is the universal "catch-all" entry present in every major password
 * manager: anything that does not fit a structured type (recovery codes,
 * private memos, instructions) can live here as a single sensitive body.
 */
@Getter
@Setter
public class SecureNote extends VaultObject {

    /**
     * Free-form note body. Considered sensitive.
     */
    private String content;

    public SecureNote(
            @NotNull String title,
            @NotNull String content,
            boolean isEncrypted
    ) {
        super("SCN", title, isEncrypted, true);
        this.content = content;
    }

    public SecureNote(
            @NotNull String id,
            @NotNull String title,
            @NotNull String content,
            @NotNull Date createdAt,
            @NotNull Date updatedAt,
            boolean isEncrypted
    ) {
        super(id, title, isEncrypted, createdAt, updatedAt, false);
        this.content = content;
    }

    @Override
    String transform(VaultEncryptingStrategy encryptor, boolean encrypt) {
        String snapshot = toString();
        super.transform(encryptor, encrypt);
        content = apply(encryptor, encrypt, content);
        return snapshot;
    }

    @Override
    public boolean share(PublicKey publicKey, VaultEncryptingStrategy vaultEncryptingStrategy) {
        return false;
    }

    @Override
    public String category() {
        return "securenotes";
    }

    @Override
    public Storable copy() {
        return new SecureNote(
                this.getId(),
                title,
                content,
                getCreatedAt(),
                getUpdatedAt(),
                isEncrypted
        );
    }

    @Override
    public String toJson() {
        JsonObject json = super.toJsonObject();
        json.addProperty("content", isEncrypted ? content : "***");
        return json.toString();
    }

    /**
     * Reconstructs a SecureNote from the JSON representation returned by the Vault.
     */
    public static SecureNote fromJson(JsonObject json) {
        return new SecureNote(
                json.get("id").getAsString(),
                json.get("title").getAsString(),
                json.get("content").getAsString(),
                java.util.Date.from(java.time.Instant.parse(json.get("createdAt").getAsString())),
                java.util.Date.from(java.time.Instant.parse(json.get("updatedAt").getAsString())),
                true
        );
    }
}
