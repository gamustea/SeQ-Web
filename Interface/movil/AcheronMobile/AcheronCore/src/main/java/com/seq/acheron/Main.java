package com.seq.acheron;

import com.seq.acheron.vault.User;
import com.seq.acheron.util.CryptoUtils;
import com.seq.acheron.util.Pair;
import com.seq.acheron.vault.Vault;
import com.seq.acheron.vault.VaultFactory;
import com.seq.acheron.vault.storables.Account;

import java.security.GeneralSecurityException;

public class Main {
    static void main() throws GeneralSecurityException {
        VaultFactory vf = VaultFactory.getInstance(
                new User(
                        "ID",
                        "Gabriel",
                        "Musteata",
                        "gmiganescu@gmail.com",
                        "gamustea"
                )
        );

        Vault mockVault = vf.mockVault();
        System.out.println("Vault mock desencriptado:\n" +
                mockVault.toJson()
        );
        Vault newVault = vf.fromJson(
                mockVault.encryptAll()
                        .toJson(),
                "Contraseña"
        );
        System.out.println("Vault encriptado: \n" + mockVault);
        System.out.println("Vault derivado desencriptado:\n" +
                newVault.decryptAll()
                        .toJson()
        );
        System.out.println("Son el mismo Vault: " + (newVault.equals(mockVault.decryptAll())));
    }
}
