package com.seq.acheron;

import com.seq.acheron.secrets.symmetric.Argon2VaultEncryptingStrategyTest;
import com.seq.acheron.secrets.symmetric.PBKDF2VaultEncryptingStrategyTest;
import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategyPerformanceTest;
import com.seq.acheron.vault.VaultTest;
import com.seq.acheron.vault.storables.AccountTest;
import com.seq.acheron.vault.storables.CreditCardTest;
import com.seq.acheron.vault.storables.VaultObjectCompareToTest;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

@Suite
@SelectClasses({
        Argon2VaultEncryptingStrategyTest.class,
        PBKDF2VaultEncryptingStrategyTest.class,
        VaultEncryptingStrategyPerformanceTest.class,
        VaultObjectCompareToTest.class,
        AccountTest.class,
        CreditCardTest.class,
        VaultTest.class,
})
public class Tests {
}
