package com.seq.acheron;

import com.seq.acheron.secrets.symmetric.AESVaultEncryptingStrategy;
import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;

import java.security.GeneralSecurityException;
import java.util.Base64;

public class Main {
    static void main() throws GeneralSecurityException {

        String MASTER_PASSWORD = "MiContraseña1234!";
        String BASE64_SALT = Base64.getEncoder().encodeToString("dhdsakjudgyhuhduawhdsjkahgduwakhdsuakhdwa".getBytes());

        VaultEncryptingStrategy opener = new AESVaultEncryptingStrategy(
                        MASTER_PASSWORD,
                        BASE64_SALT,
                true
                );

        String plaintext = "Aguacate";
        String encoded = opener.encrypt(plaintext);

        String encryptedVaultKeyString = opener.exportVaultKey();
        VaultEncryptingStrategy reopener = new AESVaultEncryptingStrategy(
                MASTER_PASSWORD,
                BASE64_SALT,
                false
        );
        reopener.importVaultKey(encryptedVaultKeyString);
        String decoded = reopener.decrypt(encoded);
        System.out.println(decoded);
    }
}
