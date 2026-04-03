package com.seq.acheron.vault.interfaces;

import com.seq.acheron.vault.storables.VaultObject;

import java.security.GeneralSecurityException;

public interface JsonSerializable {
    String toJson() throws GeneralSecurityException;
}
