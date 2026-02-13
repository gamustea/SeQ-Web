package com.seq.acheron.vault;

import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.storables.Storable;
import lombok.Getter;
import lombok.Setter;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
public class Vault {
    private final VaultEncryptingStrategy strategy;
    private final List<Storable> storables = new ArrayList<>();

    public Vault(VaultEncryptingStrategy strategy) throws NoSuchAlgorithmException {
        this.strategy = strategy;
    }

    public void addStorable(Storable storable) {
        storables.add(storable);
    }

    public void removeStorable(Storable storable) {
        storables.remove(storable);
    }

}
