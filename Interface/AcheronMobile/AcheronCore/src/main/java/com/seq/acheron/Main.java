package com.seq.acheron;

import com.google.gson.Gson;
import com.seq.acheron.agents.User;
import com.seq.acheron.secrets.symmetric.AESVaultEncryptingStrategy;
import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.Vault;
import com.seq.acheron.vault.VaultFactory;
import com.seq.acheron.vault.storables.Account;

import java.security.GeneralSecurityException;
import java.util.Base64;

public class Main {
    private static final User USER = new User(
            "dsadsad",
            "Gabriel",
            "Musteata",
            "gmiganescu@gmail.com",
            "gamustea"
    );

    static void main() throws GeneralSecurityException {


        VaultFactory vaultFactory = VaultFactory.getInstance(
                new AESVaultEncryptingStrategy(
                        "Una contraseña",
                        "aaaaaaaaadjsahdjksahndilwajdklsajdwlkadjskladwa",
                        true
                ),
                USER
        );

        String rawJson = vaultFactory
                .mockVault()
                .encryptAll()
                .toJSON();
        System.out.println(rawJson);

        Vault newVault = vaultFactory.fromJSON(rawJson);
        System.out.println(newVault.toJSON());
        System.out.println(newVault.decryptAll().toJSON());
    }
}
