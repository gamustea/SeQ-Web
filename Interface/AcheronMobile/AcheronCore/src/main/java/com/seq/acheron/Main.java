package com.seq.acheron;

import com.seq.acheron.secrets.symmetric.AESVaultEncryptingStrategy;
import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.storables.Account;

import java.security.GeneralSecurityException;
import java.util.Base64;

public class Main {
    static void main() throws GeneralSecurityException {

        Account account = new Account(
                "a",
                "a",
                "a",
                true
        );
    }
}
