# SeQ - Scanning API & Secure Vault Manager

![Java](https://img.shields.io/badge/Java-17%2B-orange)
![Maven](https://img.shields.io/badge/Maven-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

SeQ is a **comprehensive security toolkit** built in Java that provides two main functionalities:
1. **Port & Vulnerability Scanning API** - Production-ready scanning system with multi-threaded capabilities
2. **Secure Vault Manager** (Work-in-Progress) - Password manager implementing industry-standard cryptographic practices

---

## 🔍 Port & Vulnerability Scanning API

### Overview

SeQ provides a robust and flexible API for network reconnaissance, port scanning, and vulnerability detection. The scanning system is designed with performance, reliability, and ease of use in mind.

### Key Features

- **Multi-threaded Port Scanning**: Efficient concurrent scanning using Java's ExecutorService
- **Multiple Scan Types**:
  - **TCP Connect Scan**: Full TCP handshake for reliable port detection
  - **SYN Scan**: Stealthy half-open scanning (requires elevated privileges)
  - **UDP Scan**: UDP port discovery
  - **Comprehensive Scan**: Combined TCP/UDP scanning
- **Service Detection**: Automatic service identification on open ports
- **Banner Grabbing**: Capture service banners for version detection
- **Vulnerability Scanning**: Built-in CVE database integration
- **Configurable Timeouts**: Adjust scan speed vs accuracy trade-offs
- **Progress Tracking**: Real-time scan progress callbacks
- **Result Export**: JSON, XML, and CSV output formats

### Architecture

```
SeQ/
├── src/
│   ├── main/java/com/seq/acheron/
│   │   ├── scanner/
│   │   │   ├── PortScanner.java           # Main scanner interface
│   │   │   ├── ScanType.java              # Scan type enum (TCP, SYN, UDP)
│   │   │   ├── ScanResult.java            # Scan result wrapper
│   │   │   ├── PortStatus.java            # Port state enum (OPEN, CLOSED, FILTERED)
│   │   │   └── engines/
│   │   │       ├── TcpScanner.java        # TCP connect implementation
│   │   │       ├── SynScanner.java        # SYN scan implementation
│   │   │       └── UdpScanner.java        # UDP scan implementation
│   │   ├── services/
│   │   │   ├── ServiceDetector.java       # Service fingerprinting
│   │   │   ├── BannerGrabber.java         # Banner extraction
│   │   │   └── ServiceDatabase.java       # Known service signatures
│   │   ├── vuln/
│   │   │   ├── VulnerabilityScanner.java  # CVE detection engine
│   │   │   ├── CveDatabase.java           # CVE database handler
│   │   │   └── VulnerabilityReport.java   # Vulnerability result
│   │   └── export/
│   │       ├── ResultExporter.java        # Export interface
│   │       ├── JsonExporter.java          # JSON output
│   │       ├── XmlExporter.java           # XML output
│   │       └── CsvExporter.java           # CSV output
│   └── test/java/com/seq/acheron/scanner/
│       └── PortScannerTest.java           # Comprehensive test suite
```

### Usage Examples

#### Basic Port Scan

```java
import com.seq.acheron.scanner.PortScanner;
import com.seq.acheron.scanner.ScanType;
import com.seq.acheron.scanner.ScanResult;

// Create scanner instance
PortScanner scanner = new PortScanner("192.168.1.1");

// Scan common ports (1-1024)
ScanResult result = scanner.scan(1, 1024, ScanType.TCP_CONNECT);

// Print open ports
result.getOpenPorts().forEach(port -> {
    System.out.println("Port " + port + " is open");
    System.out.println("Service: " + result.getService(port));
});
```

#### Advanced Scan with Service Detection

```java
import com.seq.acheron.scanner.PortScanner;
import com.seq.acheron.services.ServiceDetector;
import com.seq.acheron.services.BannerGrabber;

PortScanner scanner = new PortScanner("example.com");
scanner.setTimeout(2000); // 2 second timeout
scanner.setThreads(50);   // Use 50 concurrent threads

// Scan with service detection
ScanResult result = scanner.scanWithServices(1, 65535, ScanType.TCP_CONNECT);

result.getOpenPorts().forEach(port -> {
    String service = result.getService(port);
    String banner = result.getBanner(port);
    
    System.out.printf("Port %d: %s - %s%n", port, service, banner);
});
```

#### Vulnerability Scanning

```java
import com.seq.acheron.scanner.PortScanner;
import com.seq.acheron.vuln.VulnerabilityScanner;
import com.seq.acheron.vuln.VulnerabilityReport;

// Perform port scan
PortScanner portScanner = new PortScanner("target.com");
ScanResult scanResult = portScanner.scanWithServices(1, 1024);

// Check for vulnerabilities
VulnerabilityScanner vulnScanner = new VulnerabilityScanner();
VulnerabilityReport report = vulnScanner.scan(scanResult);

// Print vulnerabilities
report.getVulnerabilities().forEach(vuln -> {
    System.out.println("[" + vuln.getSeverity() + "] " + vuln.getTitle());
    System.out.println("CVE: " + vuln.getCveId());
    System.out.println("Description: " + vuln.getDescription());
    System.out.println("---");
});
```

#### Export Results

```java
import com.seq.acheron.export.JsonExporter;
import com.seq.acheron.export.XmlExporter;

ScanResult result = scanner.scan(1, 1024, ScanType.TCP_CONNECT);

// Export to JSON
JsonExporter jsonExporter = new JsonExporter();
jsonExporter.export(result, "scan_results.json");

// Export to XML
XmlExporter xmlExporter = new XmlExporter();
xmlExporter.export(result, "scan_results.xml");
```

### Performance Considerations

- **Thread Pool Size**: Adjust based on target responsiveness and network bandwidth
- **Timeout Values**: Balance between scan speed and accuracy
- **Scan Type Selection**:
  - TCP Connect: Most reliable, but slower and easily detected
  - SYN Scan: Faster and stealthier, requires root/admin privileges
  - UDP Scan: Slower due to protocol characteristics

### Testing

Comprehensive test suite with JUnit 5:

```bash
mvn test
```

Test coverage includes:
- Port scanning accuracy
- Service detection validation
- Timeout handling
- Thread pool management
- Export format verification

---

## 🚧 Work-in-Progress: Secure Vault Manager

### Status: Under Development

The Secure Vault Manager is currently being developed to provide a robust password management solution. While the core cryptographic components are implemented, the vault system is not yet production-ready.

### Planned Features

- **Military-Grade Encryption**: AES-256-GCM with authenticated encryption
- **Dual KDF Support**: Argon2id (recommended) or PBKDF2 for key derivation
- **Layered Security Architecture**: Master password → Derived key → Vault key → Encrypted data
- **Multi-Entity Support**: Store accounts, credit cards, and custom secret types
- **Asymmetric Cryptography**: RSA and EC key pair management for advanced use cases
- **Zero-Knowledge Architecture**: Master password never leaves your device
- **Encryption State Tracking**: Built-in flag system to prevent double encryption/decryption errors

### Current Implementation Status

#### ✅ Completed Components

- **Cryptographic Core**:
  - `AbstractKeyPair.java` - Base key pair class
  - `RsaKeyPair.java` - RSA implementation
  - `EcKeyPair.java` - Elliptic Curve implementation
  - `VaultEncryptingStrategy.java` - Base encryption class
  - `AESVaultEncryptingStrategy.java` - Argon2 + AES-GCM
  - `PBKDF2VaultEncryptingStrategy.java` - PBKDF2 + AES-GCM

- **Entity Models**:
  - `Storable.java` - Base interface
  - `Sharable.java` - Sharing capabilities
  - `VaultObject.java` - Abstract base class
  - `Account.java` - Login credentials
  - `CreditCard.java` - Payment cards

- **User Management**:
  - `User.java` - User management with vault association

#### 🔄 In Progress

- Vault persistence layer (database/file storage)
- User interface (CLI and/or GUI)
- Vault synchronization across devices
- Secure sharing mechanisms
- Password generator
- Audit logging

#### 📋 Planned

- Browser extensions
- Mobile applications
- Auto-fill capabilities
- Biometric authentication
- Emergency access protocols

### Architecture Preview

```
SeQ/
├── src/
│   ├── main/java/com/seq/acheron/
│   │   ├── crypto/                    # ✅ Completed
│   │   │   ├── AbstractKeyPair.java
│   │   │   ├── RsaKeyPair.java
│   │   │   └── EcKeyPair.java
│   │   ├── secrets/                   # ✅ Completed
│   │   │   └── symmetric/
│   │   │       ├── VaultEncryptingStrategy.java
│   │   │       ├── AESVaultEncryptingStrategy.java
│   │   │       └── PBKDF2VaultEncryptingStrategy.java
│   │   ├── vault/                     # 🔄 In Progress
│   │   │   ├── Vault.java             # 🔄 Under development
│   │   │   ├── VaultManager.java      # 🔄 Under development
│   │   │   └── storables/             # ✅ Completed
│   │   │       ├── Storable.java
│   │   │       ├── Sharable.java
│   │   │       ├── VaultObject.java
│   │   │       ├── Account.java
│   │   │       └── CreditCard.java
│   │   ├── agents/                    # ✅ Completed
│   │   │   └── User.java
│   │   └── persistence/               # 📋 Planned
│   │       ├── VaultRepository.java   # Not yet implemented
│   │       └── DatabaseHandler.java   # Not yet implemented
```

---

## 📦 Installation

### Prerequisites

- **Java**: 17 or higher (LTS recommended)
- **Maven**: 3.8 or higher

### Dependencies (managed by Maven)

- Argon2-jvm (de.mkammerer)
- JUnit 5 (testing)
- Lombok (boilerplate reduction)

### Clone the Repository

```bash
git clone https://github.com/gamustea/SeQ.git
cd SeQ
```

### Build with Maven

```bash
mvn clean install
```

### Run Tests

```bash
mvn test
```

---

## 🎯 Use Cases

### Scanning API

- **Network Security Audits**: Discover open ports and services in your infrastructure
- **Vulnerability Assessment**: Identify potential security weaknesses
- **Penetration Testing**: Reconnaissance phase of security testing
- **Network Inventory**: Maintain up-to-date service catalogs
- **Compliance Monitoring**: Regular scans for security standards

### Vault Manager (When Complete)

- **Personal Password Management**: Secure storage for login credentials
- **Team Secrets Sharing**: Encrypted sharing of sensitive information
- **Payment Card Storage**: Secure credit card information management
- **Development Secrets**: Store API keys and tokens securely

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-scan-type`)
3. Write tests for new functionality
4. Ensure all tests pass (`mvn test`)
5. Follow existing code style (Javadoc in English)
6. Submit a pull request

---

## 📄 License

This project is licensed under the MIT License.

---

## 👤 Author

Gabriel Musteata - [@gamustea](https://github.com/gamustea)

---

## 🙏 Acknowledgments

- **Argon2**: Password-hashing function winner of the Password Hashing Competition
- **JCA/JCE**: Java Cryptography Architecture for robust encryption primitives
- **Project Lombok**: Reducing boilerplate in Java

---

## ⚠️ Disclaimer

**Scanning API**: This tool is intended for legitimate security testing on networks and systems you own or have explicit permission to test. Unauthorized port scanning or vulnerability assessment may be illegal in your jurisdiction. Always obtain proper authorization before scanning.

**Vault Manager**: The vault system is currently under development and NOT recommended for production use. While it implements industry-standard cryptographic practices, the system lacks complete testing, audit, and security review. Use at your own risk for educational purposes only.
