package com.seq.acheron.secrets.asymmetric;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * RSA implementation of {@link AbstractAsymmetricKeyPair}.
 * <p>
 * Provides factory methods to generate and reconstruct RSA key pairs.
 */
public class RsaKeyPair extends AbstractAsymmetricKeyPair {

    private static final String ALGORITHM = "RSA";

    /**
     * Creates a new {@code RsaKeyPair} from existing key objects.
     *
     * @param publicKey  RSA public key
     * @param privateKey RSA private key
     */
    public RsaKeyPair(PublicKey publicKey, PrivateKey privateKey) {
        super(publicKey, privateKey);
        if (!ALGORITHM.equalsIgnoreCase(publicKey.getAlgorithm()) ||
                !ALGORITHM.equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("Keys must be RSA");
        }
    }

    /**
     * Generates a new RSA key pair with the given key size (in bits).
     * <p>
     * Common sizes are 2048 or 3072 bits; 4096 bits can be used for
     * long-term security. [web:132][web:134]
     *
     * @param keySize the RSA modulus size in bits (e.g. 2048)
     * @return a new {@code RsaKeyPair} instance
     * @throws NoSuchAlgorithmException if RSA is not supported
     */
    public static RsaKeyPair generate(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return new RsaKeyPair(keyPair.getPublic(), keyPair.getPrivate());
    }

    /**
     * Reconstructs an {@code RsaKeyPair} from Base64-encoded
     * public and private keys.
     * <p>
     * Expects:
     * <ul>
     *     <li>Public key in X.509 / SubjectPublicKeyInfo format</li>
     *     <li>Private key in PKCS#8 format</li>
     * </ul>
     *
     * @param base64PublicKey  Base64-encoded RSA public key
     * @param base64PrivateKey Base64-encoded RSA private key
     * @return the reconstructed {@code RsaKeyPair}
     * @throws NoSuchAlgorithmException if RSA is not supported
     * @throws InvalidKeySpecException  if key data is malformed
     */
    public static RsaKeyPair fromBase64(String base64PublicKey, String base64PrivateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

        byte[] publicBytes = Base64.getDecoder().decode(base64PublicKey);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(publicBytes);
        PublicKey publicKey = keyFactory.generatePublic(pubSpec);

        byte[] privateBytes = Base64.getDecoder().decode(base64PrivateKey);
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privateBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privSpec);

        return new RsaKeyPair(publicKey, privateKey);
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }
}
