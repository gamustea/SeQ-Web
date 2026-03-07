package com.seq.acheron.vault.interfaces;

import com.seq.acheron.vault.User;
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;

import java.security.PublicKey;
import java.util.Set;

public interface Sharable {
    Set<User> getAllowedUsers();
    boolean isAllowed(User user);
    boolean revoke(User user);
    boolean share(PublicKey publicKey, VaultEncryptingStrategy vaultEncryptingStrategy);
}
