package com.seq.acheron;

import com.seq.acheron.util.Pair;
import com.seq.acheron.vault.User;
import com.seq.acheron.vault.Vault;
import com.seq.acheron.vault.VaultFactory;

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

        Vault mockVault = vf.getMockVault();
        Pair<Vault, String> pair = vf.getRestorationVault(mockVault);
        System.out.println("La cotraseña es: " + pair.right());

        Vault newVault = vf.fromJson(
                pair.left()
                        .encryptAll()
                        .toJson(),
                pair.right()
        );

        System.out.println("Vault encriptado");
        System.out.println(newVault);
        System.out.println("Vault desencriptado");
        System.out.println(newVault.decryptAll());
    }
}
