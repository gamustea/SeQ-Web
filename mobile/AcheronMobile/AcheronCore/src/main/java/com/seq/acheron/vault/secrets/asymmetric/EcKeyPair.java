package com.seq.acheron.vault.secrets.asymmetric;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Elliptic Curve implementation of {@link AbstractAsymmetricKeyPair}.
 * <p>
 * This class uses standard named curves (e.g. "secp256r1") and the
 * JCA "EC" algorithm. It can be used for ECDSA, ECDH, etc.,
 * depending on how you use the keys.
 */
public class EcKeyPair extends AbstractAsymmetricKeyPair {

    private static final String ALGORITHM = "EC";

    /**
     * Standard curve name used by default, e.g. NIST P-256.
     * <p>
     * Also known as "prime256v1". [web:147][web:154]
     */
    public static final String DEFAULT_CURVE = "secp256r1";

    /**
     * Creates a new {@code EcKeyPair} from existing key objects.
     *
     * @param publicKey  EC public key
     * @param privateKey EC private key
     */
    public EcKeyPair(PublicKey publicKey, PrivateKey privateKey) {
        super(publicKey, privateKey);
        if (!ALGORITHM.equalsIgnoreCase(publicKey.getAlgorithm()) ||
                !ALGORITHM.equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("Keys must be EC");
        }
    }

    /**
     * Generates a new EC key pair using the given named curve.
     * <p>
     * For example, {@code "secp256r1"} is a widely used NIST P-256 curve. [web:147][web:154]
     *
     * @param curveName the standard curve name (e.g. "secp256r1")
     * @return a new {@code EcKeyPair} instance
     * @throws GeneralSecurityException if the algorithm or curve is not supported
     */
    public static EcKeyPair generate(String curveName) throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return new EcKeyPair(keyPair.getPublic(), keyPair.getPrivate());
    }

    /**
     * Generates a new EC key pair using {@link #DEFAULT_CURVE}.
     *
     * @return a new {@code EcKeyPair} instance
     * @throws GeneralSecurityException if the algorithm or curve is not supported
     */
    public static EcKeyPair generateDefault() throws GeneralSecurityException {
        return generate(DEFAULT_CURVE);
    }

    /**
     * Reconstructs an {@code EcKeyPair} from Base64-encoded public
     * and private keys.
     * <p>
     * Expects:
     * <ul>
     *     <li>Public key in X.509 / SubjectPublicKeyInfo format</li>
     *     <li>Private key in PKCS#8 format</li>
     * </ul>
     *
     * @param base64PublicKey  Base64-encoded EC public key
     * @param base64PrivateKey Base64-encoded EC private key
     * @return the reconstructed {@code EcKeyPair}
     * @throws NoSuchAlgorithmException if EC is not supported
     * @throws InvalidKeySpecException  if key data is malformed
     */
    public static EcKeyPair fromBase64(String base64PublicKey, String base64PrivateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

        byte[] publicBytes = Base64.getDecoder().decode(base64PublicKey);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(publicBytes);
        PublicKey publicKey = keyFactory.generatePublic(pubSpec);

        byte[] privateBytes = Base64.getDecoder().decode(base64PrivateKey);
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privateBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privSpec);

        return new EcKeyPair(publicKey, privateKey);
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }
}
