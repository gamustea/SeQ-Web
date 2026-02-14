# SeQ - Secure Vault Manager

![Java](https://img.shields.io/badge/Java-17%2B-orange)
![Maven](https://img.shields.io/badge/Maven-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

SeQ is a **secure password manager and vault system** built in Java that implements industry-standard cryptographic practices to protect sensitive data such as passwords, credit cards, and other secrets.

## 🔐 Features

- **Military-Grade Encryption**: AES-256-GCM with authenticated encryption
- **Dual KDF Support**: Choose between Argon2id (recommended) or PBKDF2 for key derivation
- **Layered Security Architecture**: Master password → Derived key → Vault key → Encrypted data
- **Multi-Entity Support**: Store accounts, credit cards, and custom secret types
- **Asymmetric Cryptography**: RSA and EC key pair management for advanced use cases
- **Encryption State Tracking**: Built-in flag system to prevent double encryption/decryption errors
- **Zero-Knowledge Architecture**: Your master password never leaves your device
- **Comprehensive Testing**: Full JUnit 5 test coverage with encryption cycle validation

## 🏗 Architecture

```
SeQ/
├── src/
│   ├── main/java/com/seq/acheron/
│   │   ├── crypto/                    # Asymmetric cryptography
│   │   │   ├── AbstractKeyPair.java   # Base key pair class
│   │   │   ├── RsaKeyPair.java        # RSA implementation
│   │   │   └── EcKeyPair.java         # Elliptic Curve implementation
│   │   ├── secrets/
│   │   │   └── symmetric/             # Symmetric encryption strategies
│   │   │       ├── VaultEncryptingStrategy.java      # Base encryption class
│   │   │       ├── AESVaultEncryptingStrategy.java   # Argon2 + AES-GCM
│   │   │       └── PBKDF2VaultEncryptingStrategy.java # PBKDF2 + AES-GCM
│   │   ├── vault/
│   │   │   └── storables/             # Vault entities
│   │   │       ├── Storable.java      # Base interface
│   │   │       ├── Sharable.java      # Sharing capabilities
│   │   │       ├── VaultObject.java   # Abstract base class
│   │   │       ├── Account.java       # Login credentials
│   │   │       └── CreditCard.java    # Payment cards
│   │   └── agents/
│   │       └── User.java              # User management
│   └── test/java/                     # Comprehensive test suite
└── pom.xml
```

## 🔑 How It Works

### Encryption Flow

1. **Master Password**: User provides a master password
2. **Key Derivation**: Argon2id/PBKDF2 derives a 256-bit key from master + salt
3. **Vault Key Generation**: A random 256-bit AES key is generated for the vault
4. **Key Wrapping**: The vault key is encrypted using the derived key
5. **Data Encryption**: Vault contents are encrypted with the vault key using AES-256-GCM

### Security Benefits

- **Password Rotation**: Change your master password without re-encrypting the entire vault
- **Multi-User Support**: Share vault keys securely using asymmetric encryption
- **Forward Secrecy**: Each encryption operation uses a unique random IV
- **Authentication**: GCM mode provides both encryption and authentication

## 📦 Prerequisites

- **Java**: 17 or higher (LTS recommended)
- **Maven**: 3.8 or higher
- **Dependencies** (managed by Maven):
  - Argon2-jvm (de.mkammerer)
  - JUnit 5 (testing)
  - Lombok (boilerplate reduction)

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/gamustea/SeQ.git
cd SeQ
```

### 2. Build with Maven

```bash
mvn clean install
```

### 3. Run Tests

```bash
mvn test
```

All tests should pass, confirming encryption/decryption cycles work correctly.

## 💻 Usage Examples

### Creating a Vault with Argon2

```java
import com.seq.acheron.secrets.symmetric.*;
import com.seq.acheron.vault.storables.*;
import java.util.Base64;

// 1. Generate a salt for the user (store this!)
SecureRandom random = new SecureRandom();
byte[] salt = new byte[16];
random.nextBytes(salt);
String saltBase64 = Base64.getEncoder().encodeToString(salt);

// 2. Create encryption strategy with master password
String masterPassword = "MySecurePassword123!";
AESVaultEncryptingStrategy strategy = 
    new AESVaultEncryptingStrategy(masterPassword, saltBase64);

// 3. Export encrypted vault key (store this!)
String encryptedVaultKey = strategy.exportVaultKey();

// 4. Create and encrypt vault objects
Account githubAccount = new Account("user@example.com", "github.com", "MyGitHubPass", false);
githubAccount.encrypt(strategy);

// Now githubAccount.getPassword() contains encrypted data
```

### Reopening an Existing Vault

```java
// 1. User provides master password again
String masterPassword = "MySecurePassword123!";
String saltBase64 = // ... retrieve from storage
String encryptedVaultKey = // ... retrieve from storage

// 2. Recreate strategy to derive key
AESVaultEncryptingStrategy tempStrategy = 
    new AESVaultEncryptingStrategy(masterPassword, saltBase64);

// 3. Unwrap vault key
SecretKey vaultKey = tempStrategy.importVaultKey(encryptedVaultKey);

// 4. Create strategy with imported vault key
AESVaultEncryptingStrategy strategy = 
    new AESVaultEncryptingStrategy(masterPassword, saltBase64, vaultKey);

// 5. Load and decrypt vault objects
Account githubAccount = // ... load from storage (with encrypted password)
githubAccount.decrypt(strategy);

// Now githubAccount.getPassword() contains plain-text password
```

### Working with Credit Cards

```java
CreditCard myCard = new CreditCard(
    "John Doe",
    "4111111111111111",
    "12/29",
    "123",
    "28001",
    false  // isEncrypted = false (plain-text)
);

// Encrypt all sensitive fields
myCard.encrypt(strategy);

// Card data is now encrypted
assertTrue(myCard.isEncrypted());

// Decrypt when needed
myCard.decrypt(strategy);
assertEquals("4111111111111111", myCard.getCardNumber());
```

## 🔬 Cryptographic Details

### Key Derivation Functions

#### Argon2id (Recommended)
- **Algorithm**: Argon2id (hybrid mode)
- **Parameters**: 3 iterations, 64 MB memory, 1 parallelism
- **Output**: 256-bit key
- **Resistance**: Memory-hard, GPU-resistant

#### PBKDF2
- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 600,000 (OWASP recommendation)
- **Output**: 256-bit key
- **Use case**: Legacy compatibility

### Symmetric Encryption

- **Algorithm**: AES-256-GCM
- **Key size**: 256 bits
- **IV size**: 96 bits (12 bytes), randomly generated per encryption
- **Tag size**: 128 bits (provides authentication)
- **Mode**: Galois/Counter Mode (authenticated encryption)

### Asymmetric Cryptography

#### RSA
- **Key sizes**: 2048, 3072, or 4096 bits
- **Format**: PKCS#8 (private), X.509 (public)
- **Use case**: Vault key sharing, digital signatures

#### Elliptic Curve
- **Curves**: secp256r1 (NIST P-256) by default
- **Format**: PKCS#8 (private), X.509 (public)
- **Use case**: Efficient key exchange (ECDH)

## 🧪 Testing

### Running All Tests

```bash
mvn test
```

### Test Coverage

- **Encryption Strategies**: AES (Argon2) and PBKDF2 full encryption/decryption cycles
- **Vault Objects**: Account and CreditCard field encryption validation
- **State Management**: `isEncrypted` flag correctness
- **Error Cases**: Double encryption/decryption prevention
- **Key Management**: Vault key export/import cycles

### Sample Test Output

```
[OK] AESEncryptingStrategy.encryptThenDecrypt_returnsOriginalPlaintext
[OK] AESEncryptingStrategy.exportAndImportVaultKey_reopenWithSameMaster_canDecryptOldData
[OK] Account.encryptThenDecrypt_restoresOriginalFields
[OK] Account.idsHaveAccPrefixAndIncrementPerInstance
[OK] Account.isEncryptedFlag_becomesTrue_afterEncryption
[OK] CreditCard.encryptTwice_throwsIllegalStateException
```

## 🛡 Security Best Practices

### When Using This Library

1. **Never hardcode passwords**: Always prompt users for their master password
2. **Use secure random**: Generate salts with `SecureRandom`
3. **Store safely**: Keep encrypted vault keys and salts in secure storage
4. **Wipe sensitive data**: Clear password char arrays after use
5. **Validate input**: Check master password strength before use
6. **Use Argon2**: Prefer `AESVaultEncryptingStrategy` over PBKDF2 when possible

### What This Library Does NOT Do

- **Network communication**: No built-in sync or cloud backup
- **Password generation**: Use a separate library for password generation
- **Biometric auth**: Integrate with platform-specific APIs separately
- **Auto-fill**: UI/UX integration is application-specific

## 📚 API Documentation

### Core Interfaces

#### `Storable`
```java
public interface Storable {
    String getId();
    String encrypt(VaultEncryptingStrategy strategy);
    String decrypt(VaultEncryptingStrategy strategy);
}
```

#### `VaultEncryptingStrategy`
```java
public abstract class VaultEncryptingStrategy {
    public String encrypt(String plainText) throws GeneralSecurityException;
    public String decrypt(String ciphertext) throws GeneralSecurityException;
    public String exportVaultKey() throws GeneralSecurityException;
    public SecretKey importVaultKey(String encryptedVaultKey) throws GeneralSecurityException;
}
```

### Vault Objects

#### `Account`
- `username`: Login username
- `domain`: Service domain (e.g., "github.com")
- `password`: Encrypted/plain-text password

#### `CreditCard`
- `cardHolderName`: Name on card
- `cardNumber`: Card PAN (encrypted)
- `expirationDate`: MM/YY format
- `cvv`: Security code (encrypted)
- `postalCode`: Billing ZIP

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-entity-type`)
3. Write tests for new functionality
4. Ensure all tests pass (`mvn test`)
5. Follow existing code style (Javadoc in English)
6. Submit a pull request

## 📝 License

This project is licensed under the MIT License.

## 👨‍💻 Author

**Gabriel Musteata** - [@gamustea](https://github.com/gamustea)

## 🙏 Acknowledgments

- **Argon2**: Password-hashing function winner of the Password Hashing Competition
- **JCA/JCE**: Java Cryptography Architecture for robust encryption primitives
- **Project Lombok**: Reducing boilerplate in Java

---

**⚠️ Disclaimer**: This library is provided as-is for educational and production use. While it implements industry-standard cryptographic practices, users are responsible for secure key management, proper salt generation, and overall system security. Always conduct security audits before using in critical applications.
