package com.seq.acheron.vault;

import java.security.GeneralSecurityException;

public interface JsonSerializable {
    String toJson() throws GeneralSecurityException;
}
