package com.seq.acheron.vault.interfaces;

import java.security.GeneralSecurityException;

public interface JsonSerializable {
    String toJson() throws GeneralSecurityException;
}
