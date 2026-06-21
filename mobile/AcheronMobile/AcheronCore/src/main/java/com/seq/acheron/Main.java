package com.seq.acheron;

import com.seq.acheron.util.Pair;
import com.seq.acheron.vault.User;
import com.seq.acheron.vault.Vault;
import com.seq.acheron.vault.VaultFactory;

import java.security.GeneralSecurityException;

public class Main {
    static void main() throws GeneralSecurityException {
        VaultFactory vf = new VaultFactory(
                new User(
                        "ID",
                        "Gabriel",
                        "Musteata",
                        "gmiganescu@gmail.com",
                        "gamustea"
                )
        );

        Vault mockVault = vf.getMockVault();

        mockVault.encryptAll();
        System.out.println("Vault encriptado");
        System.out.println(mockVault);

        mockVault.decryptAll();
        System.out.println("Vault desencriptado");
        System.out.println("Storables: " + mockVault.getStorables().size());
    }
}
