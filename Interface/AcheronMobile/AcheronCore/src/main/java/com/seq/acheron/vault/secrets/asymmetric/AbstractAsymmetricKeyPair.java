package com.seq.acheron.vault.secrets.asymmetric;

import lombok.Getter;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Abstract base class representing an asymmetric key pair,
 * consisting of a public key and a private key.
 * <p>
 * Concrete subclasses (e.g. RSA, EC) provide the actual key
 * generation and import logic for a specific algorithm.
 */
@Getter
public abstract class AbstractAsymmetricKeyPair {


    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    /**
     * Creates an {@code AbstractKeyPair} from existing key objects.
     *
     * @param publicKey  the public key, must not be {@code null}
     * @param privateKey the private key, must not be {@code null}
     */
    protected AbstractAsymmetricKeyPair(PublicKey publicKey, PrivateKey privateKey) {
        if (publicKey == null || privateKey == null) {
            throw new IllegalArgumentException("Keys must not be null");
        }
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    /**
     * Returns the algorithm name (e.g. "RSA", "EC") for this key pair.
     *
     * @return the algorithm identifier
     */
    public abstract String getAlgorithm();

    /**
     * Exports the public key to a Base64-encoded string.
     * <p>
     * The binary format (e.g. X.509 / SubjectPublicKeyInfo) depends on
     * the specific algorithm and provider implementation.
     *
     * @return the Base64 representation of the encoded public key
     */
    public String exportPublicKeyBase64() {
        byte[] encoded = publicKey.getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }

    /**
     * Exports the private key to a Base64-encoded string.
     * <p>
     * The binary format (e.g. PKCS#8) depends on the specific algorithm
     * and provider implementation. Handle this value with great care.
     *
     * @return the Base64 representation of the encoded private key
     */
    public String exportPrivateKeyBase64() {
        byte[] encoded = privateKey.getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }

    /**
     * Returns a non-sensitive, human-readable description of this key pair.
     *
     * @return a short string describing algorithm and formats
     */
    @Override
    public String toString() {
        return getAlgorithm() + "KeyPair{" +
                "publicKeyFormat=" + publicKey.getFormat() +
                ", privateKeyFormat=" + privateKey.getFormat() +
                '}';
    }
}
