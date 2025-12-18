DROP DATABASE IF EXISTS SecOps;
CREATE DATABASE IF NOT EXISTS SecOps;

USE SecOps;

CREATE TABLE Person (
	id INTEGER PRIMARY KEY AUTO_INCREMENT,
	first_name VARCHAR(64) NOT NULL,
	last_name VARCHAR(64) NOT NULL,
	email VARCHAR(128) NOT NULL UNIQUE,
	created_at DATETIME NOT NULL
);

CREATE TABLE User (
	id INTEGER PRIMARY KEY AUTO_INCREMENT,
	username VARCHAR(64) NOT NULL UNIQUE,
	password_hash VARCHAR(128) NOT NULL,
    password_salt varchar(128) NOT NULL,
	person_id INTEGER NOT NULL,
	FOREIGN KEY (person_id) REFERENCES Person (id)
);

CREATE TABLE Scan (
	`id` INTEGER PRIMARY KEY AUTO_INCREMENT,
	`target` VARCHAR(255) NOT NULL,
	`started_at` DATETIME NOT NULL,
	`user_id` INTEGER NOT NULL,
	`scan_type` VARCHAR(50),
	FOREIGN KEY (`user_id`) REFERENCES `User` (`id`)
);

CREATE TABLE FinishedScan (
	id INTEGER PRIMARY KEY,
	finished_at DATETIME NOT NULL,
	FOREIGN KEY (id) REFERENCES Scan (id)
);

CREATE TABLE NmapScan (
	id INTEGER PRIMARY KEY,
	FOREIGN KEY (id) REFERENCES Scan (id)
);

CREATE TABLE Port (
	id INTEGER PRIMARY KEY AUTO_INCREMENT,
	protocol VARCHAR(255) UNIQUE
);

CREATE TABLE TargetPort (
	port_id INTEGER,
	nmap_scan_id INTEGER,
	PRIMARY KEY (port_id, nmap_scan_id),
	FOREIGN KEY (port_id) REFERENCES Port (id),
	FOREIGN KEY (nmap_scan_id) REFERENCES NmapScan (id)
);

CREATE TABLE OpenPort (
	port_id INTEGER,
	nmap_scan_id INTEGER,
	reason VARCHAR(255) NOT NULL,
	PRIMARY KEY (port_id, nmap_scan_id),
	FOREIGN KEY (port_id) REFERENCES Port (id),
	FOREIGN KEY (nmap_scan_id) REFERENCES NmapScan (id)
);

CREATE TABLE NiktoScan (
	id INTEGER PRIMARY KEY,
	FOREIGN KEY (id) REFERENCES Scan (id)
);

CREATE TABLE `NiktoIncident` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `osvdb_id` VARCHAR(20),              -- ID de OSVDB (ej: "OSVDB-3268")
  `method` VARCHAR(10),                -- Método HTTP (GET, POST, etc.)
  `url` VARCHAR(512) NOT NULL,         -- URL completa del incidente
  `description` TEXT NOT NULL,         -- Descripción del incidente
  `severity` VARCHAR(20),              -- Severidad: low, medium, high, critical
  `ip_address` VARCHAR(45),            -- IP del host afectado
  `port` INTEGER,                      -- Puerto donde se detectó
  `references` TEXT,                   -- Enlaces de referencia (CVE, etc.)
  `discovered_at` DATETIME NOT NULL   -- Momento del descubrimiento
);

CREATE TABLE ScanIncident (
	nikto_scan_id INTEGER,
	nikto_incident_id INTEGER,
	PRIMARY KEY (nikto_scan_id, nikto_incident_id),
	FOREIGN KEY (nikto_scan_id) REFERENCES NiktoScan (id),
	FOREIGN KEY (nikto_incident_id) REFERENCES NiktoIncident (id)
);

CREATE TABLE OpenVASScan (
	id INTEGER PRIMARY KEY,
	FOREIGN KEY (id) REFERENCES Scan (id)
);

CREATE TABLE AccessToken (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(512) NOT NULL UNIQUE,
    user_id INT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked TINYINT DEFAULT 0,
    INDEX idx_token (token),
    INDEX idx_user (user_id),
    FOREIGN KEY (user_id) REFERENCES User(id) ON DELETE CASCADE
);

CREATE TABLE RefreshToken (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(512) NOT NULL UNIQUE,
    user_id INT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked TINYINT DEFAULT 0,
    INDEX idx_token (token),
    INDEX idx_user (user_id),
    FOREIGN KEY (user_id) REFERENCES User(id) ON DELETE CASCADE
);

CREATE TABLE Subscription (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,
    plan ENUM('FREE', 'BASIC', 'PREMIUM', 'ENTERPRISE') NOT NULL DEFAULT 'free',
    status ENUM('ACTIVE', 'EXPIRED', 'CANCELLED', 'SUSPENDED', 'TRIAL') NOT NULL DEFAULT 'trial',
    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NULL,
    last_payment_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    auto_renew TINYINT(1) DEFAULT 0,
    max_scans_per_day INT DEFAULT 5,
    max_concurrent_scans INT DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES User(id) ON DELETE CASCADE,
    INDEX idx_user (user_id),
    INDEX idx_status (status),
    INDEX idx_expires (expires_at)
);

CREATE TABLE Payment (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    subscription_id INT NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    payment_method VARCHAR(50) NULL,
    transaction_id VARCHAR(255) UNIQUE NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    paid_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES User(id) ON DELETE CASCADE,
    FOREIGN KEY (subscription_id) REFERENCES Subscription(id) ON DELETE CASCADE,
    INDEX idx_user (user_id),
    INDEX idx_subscription (subscription_id),
    INDEX idx_transaction (transaction_id)
);

    