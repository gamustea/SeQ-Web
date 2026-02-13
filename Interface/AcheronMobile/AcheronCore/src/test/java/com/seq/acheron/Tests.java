package com.seq.acheron;

import com.seq.acheron.secrets.symmetric.AESVaultEncryptingStrategyTest;
import com.seq.acheron.secrets.symmetric.PBKDF2VaultEncryptingStrategyTest;
import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategyPerformanceTest;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

@Suite
@SelectClasses({
        AESVaultEncryptingStrategyTest.class,
        PBKDF2VaultEncryptingStrategyTest.class,
        VaultEncryptingStrategyPerformanceTest.class
})
public class Tests {
}
