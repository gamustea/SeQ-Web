package com.seq.acheron;

import com.seq.acheron.agents.User;
import com.seq.acheron.secrets.symmetric.AESVaultEncryptingStrategy;
import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.util.CryptoUtils;
import com.seq.acheron.util.Pair;
import com.seq.acheron.vault.Vault;
import com.seq.acheron.vault.VaultFactory;

import java.security.GeneralSecurityException;

public class Main {

    private static final User USER = new User(
            "dsadsad",
            "Gabriel",
            "Musteata",
            "gmiganescu@gmail.com",
            "gamustea"
    );

    private static final String MASTER_PASSWORD = "Una contraseña";
    private static final String SALT = CryptoUtils.generateSalt();

    static void main() throws GeneralSecurityException {
        VaultFactory factory = VaultFactory.getInstance(
                USER
        );

        Vault mockVault = factory.mockVault(USER).encryptAll();
        System.out.println("VAULT: " + mockVault);

        Vault vault = factory.fromJSON(
                mockVault.toJson(),
                "CONTRASEÑA"
        );
        System.out.println(vault);
        vault.decryptAll();
        vault.encryptAll();
        System.out.println(vault.decryptAll());

        Pair<Vault, String> pair = factory.getRestorationVault(vault);
        Vault restorationVault = pair.left();
        String restorationKey = pair.right();

        Vault newVault = factory.fromJSON(restorationVault.encryptAll().toJson(), restorationKey);
        System.out.println(newVault);
        System.out.println(newVault.decryptAll());
        System.out.println(newVault.encryptAll());
    }
}
