package com.seq.acheron.vault;

import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.storables.Storable;
import com.seq.acheron.vault.storables.VaultObject;
import lombok.Getter;
import org.jetbrains.annotations.NotNull;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;

@Getter
public class Vault {
    private final VaultEncryptingStrategy strategy;
    private final List<Storable> storables = new ArrayList<>();
    private boolean isEncrypted;

    public Vault(VaultEncryptingStrategy strategy) throws NoSuchAlgorithmException {
        this.strategy = strategy;
    }

    public Storable get(String id) {
        return storables.stream()
                .filter(storable -> storable.getId().equals(id))
                .findFirst()
                .orElse(null);
    }

    public void add(Storable storable) {
        storables.add(storable);
    }

    public void remove(Storable storable) {
        storables.remove(storable);
    }

    public void encryptAll()  {
        toggleEncrypt(true);
    }

    public void decryptAll() {
        toggleEncrypt(false);
    }

    private void toggleEncrypt(boolean encrypt) {
        for (Storable storable : storables) {
            if (encrypt && !isEncrypted || !encrypt && isEncrypted) {
                throw new IllegalStateException("Encrypted storables are currently being encrypted");
            }

            if (encrypt) {
                storable.decrypt(strategy);
            } else {
                storable.encrypt(strategy);
            }
        }
        isEncrypted = encrypt;
    }
}
