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
        System.out.println(
                vf.mockVault()
                        .encryptAll()
                        .toJson()
        );
    }
}
