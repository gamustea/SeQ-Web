package com.seq.acheron;

import com.seq.acheron.agents.User;
import com.seq.acheron.secrets.symmetric.AESVaultEncryptingStrategy;
import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.Vault;
import com.seq.acheron.vault.VaultFactory;

import java.security.GeneralSecurityException;

public class Main {

    private static final User USER = new User(
            "dsadsad",
            "Gabriel",
            "Musteata",
            "gmiganescu@gmail.com",
            "gamustea"
    );

    private static final String MASTER_PASSWORD = "Una contraseña";
    private static final String SALT = "aaaaaaaaadjsahdjksahndilwajdklsajdwlkadjskladwa";

    static void main() throws GeneralSecurityException {
        VaultFactory factory = VaultFactory.getInstance(
                USER
        );

        Vault vault = factory.fromJSON("{\"checker\": \"H7v0BR/fuKOK0lSpQC/J+HU8whvH+1MLF2rEzUiaa87Zyx4YDWxy2RIPva61Sz0oPb3nx5s/W3CYqmNatO37gDxE3gPUcuiFkB4sQ6Ot1jf9asw7yTDKCE4EUoc=\", \"vaultKey\": \"1/a6UFNqRFpYLC5vUQ9SiRDZFWnktqudB2i2pX9DomU9ZowZ+Y13Yahkig/wpffAn/iiUWnweCEVvlQE1pEF2k0CF+3yXCrW\", \"creditcards\": [{\"id\": \"CDC3\", \"createdAt\": \"Sat Feb 21 16:33:39 CET 2026\", \"updatedAt\": \"Sat Feb 21 16:33:39 CET 2026\", \"allowedUsers\": [], \"cardHolderName\": \"7+CdZPbsqgV+BdVfK6naMOq4yXUgzSGxhmtjn1TwCxgHM19iTbL3E30NuVE=\", \"cardNumber\": \"2CXktZLd7otIWEBqhgCNHLtDYCL4D0LIoClPX+lwg1BFbjuhin76HhyOPws=\", \"expirationDate\": \"nPRXz+Q9qK4nye0Te2C/Ir2Bw+7rfw26E3pUhy+DEUif\", \"postalCode\": \"LCO4YD3VH1+8fsg+y8SAu5AFmmTbH//kG6j6xfsKPcKO\", \"cvv\": \"WsWIAEINYldnNFy+rSTjYKATBjViaRfw4rGepmQQXw==\"}, {\"id\": \"CDC4\", \"createdAt\": \"Sat Feb 21 16:33:39 CET 2026\", \"updatedAt\": \"Sat Feb 21 16:33:39 CET 2026\", \"allowedUsers\": [], \"cardHolderName\": \"TZIeUzFmOjmZPGp+lP9zjmb9fRa6XGpaKVAhtdOj8gzniBx99a41yXfIVpM=\", \"cardNumber\": \"flzWn5boGD1aa2ge67LUrE8RiI/yLj0GZm07pJrDZMQ+PW9/Ls5b8qGk3XM=\", \"expirationDate\": \"+LQ1bwht8/2UBmqgW1c1xk6xk6ZDHsItz/vdpejHRNMt\", \"postalCode\": \"/EV3Rtg7EggmxilOP+JN5pdSIRgEkM/EAgumCrnBxfqn\", \"cvv\": \"MUcQ4wyK7DXNTiBtgkBAEbVs1JTB4ag/l6b5iyl1hg==\"}], \"accounts\": [{\"id\": \"ACC0\", \"createdAt\": \"Sat Feb 21 16:33:39 CET 2026\", \"updatedAt\": \"Sat Feb 21 16:33:39 CET 2026\", \"allowedUsers\": [], \"username\":\"8EjJEoHOLR4pWsHHm+RBumZXo0Rtk97vAIcVMBMgyzjmdebsiZTEhKrb\", \"domain\":\"9qF4LTbVZul7mFCm+DgYVJZQcB0R8v/fPeR7/yBRkgVujUyCg5USSMmgbg==\", \"password\":\"b7yqlQ9RM+WfYXPaue/aERexd/qo+ju2Q3OcJwmKBN3TtIOixC0jKg==\"}, {\"id\": \"ACC1\", \"createdAt\": \"Sat Feb 21 16:33:39 CET 2026\", \"updatedAt\": \"Sat Feb 21 16:33:39 CET 2026\", \"allowedUsers\": [], \"username\":\"vjPlaC8g1rDyl2n9I5b1HXCTSu2ZAI5r6dSBjCH8GZvVItH5\", \"domain\":\"46cCDK9KwWHBaT/8XDPPHuvJTi5xOHRLxsiB63NJREik02zmQ+U=\", \"password\":\"luBPkxsxIXTEH0jWRFzwA240nrqyaujszQr669uWKUDNxbuWP0vaacvtTQ==\"}, {\"id\": \"ACC2\", \"createdAt\": \"Sat Feb 21 16:33:39 CET 2026\", \"updatedAt\": \"Sat Feb 21 16:33:39 CET 2026\", \"allowedUsers\": [], \"username\":\"FLmfPFtFjHV2DIyJHeiEsPMofuGGwTOY/0Fn8n9Xly/ybcuLL+TKjnEz\", \"domain\":\"wT3rQAqskfWEPA2Wu9OosbfXU1kYZVJ4V5Fvuy+kMiNk97S3H7Yg\", \"password\":\"cqeKj6pQfMF5OSrj7F9jn0VUU92CGAqYPcSZxUW5TD/GhhnXnXMNRQ==\"}]}\n",
                new AESVaultEncryptingStrategy(MASTER_PASSWORD, SALT, false)
        );
        System.out.println(vault.decryptAll());
    }
}
