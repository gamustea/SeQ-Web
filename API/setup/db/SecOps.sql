DROP DATABASE IF EXISTS SecOps;
CREATE DATABASE IF NOT EXISTS SecOps;

USE SecOps;

CREATE TABLE Person (
	id INTEGER PRIMARY KEY AUTO_INCREMENT,
	first_name VARCHAR(64) NOT NULL,
	last_name VARCHAR(64) NOT NULL,
    alias VARCHAR(64) NOT NULL UNIQUE,
	created_at DATETIME NOT NULL
);

CREATE TABLE Rol (
	id INTEGER PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(32) UNIQUE NOT NULL,
    hierarchy_level INTEGER NOT NULL,
    description VARCHAR(128)
);

CREATE TABLE User (
	id INTEGER PRIMARY KEY AUTO_INCREMENT,
	username VARCHAR(64) NOT NULL UNIQUE,
	password_hash VARCHAR(128) NOT NULL,
    password_salt varchar(128) NOT NULL,
    email VARCHAR(128) NOT NULL UNIQUE,
	person_id INTEGER NOT NULL,
    rol_id INTEGER NOT NULL,
    FOREIGN KEY (rol_id) REFERENCES Rol (id),
	FOREIGN KEY (person_id) REFERENCES Person (id)
);

CREATE TABLE Host (
	id INTEGER PRIMARY KEY AUTO_INCREMENT,
    hostname VARCHAR(64) UNIQUE NOT NULL,
    ip_address VARCHAR(15) NOT NULL,
    mac_address VARCHAR(17),
    vendor VARCHAR(64)
);

CREATE TABLE Scan (
	`id` INTEGER PRIMARY KEY AUTO_INCREMENT,
	`target` VARCHAR(255) NOT NULL,
	`started_at` DATETIME NOT NULL,
    `status` VARCHAR(20) NOT NULL DEFAULT 'pending',
	`user_id` INTEGER NOT NULL,
	`scan_type` VARCHAR(50),
    frecuent BOOLEAN NOT NULL DEFAULT false,
    host_id INTEGER,
	FOREIGN KEY (`user_id`) REFERENCES `User` (`id`),
    FOREIGN KEY (host_id) REFERENCES Host (id)
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
    product Varchar(255),
    version VARCHAR(64),
    given_use VARCHAR(255),
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

-- Tabla OpenVASScan (sin cambios, hereda de Scan)
CREATE TABLE OpenVASScan (
    id INTEGER PRIMARY KEY,
    task_id VARCHAR(255) NOT NULL,
    report_id VARCHAR(255) NOT NULL,
    scan_config_name VARCHAR(255),
    scanner_name VARCHAR(255),
    
    FOREIGN KEY (id) REFERENCES Scan (id),
    UNIQUE(task_id, report_id)
);

-- OpenVASVulnerability (sin cambios)
CREATE TABLE OpenVASVulnerability (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    nvt_oid VARCHAR(255) UNIQUE NOT NULL,
    name TEXT NOT NULL,

    severity_score DECIMAL(3,1),
    severity_class VARCHAR(20),
    cvss_base_score DECIMAL(3,1),
    cvss_vector VARCHAR(255),
    
    cve_ids TEXT,
    cert_refs TEXT,
    bugtraq_ids TEXT,
    other_refs TEXT,
    
    summary TEXT,
    description TEXT,
    impact TEXT,
    insight TEXT,
    affected_software TEXT,
    
    solution_type VARCHAR(50),
    solution TEXT,
    
    qod_value INTEGER,
    qod_type VARCHAR(100),
    
    family VARCHAR(255),
    category VARCHAR(255),
    
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_nvt_oid (nvt_oid),
    INDEX idx_severity_class (severity_class)
);

CREATE TABLE OpenVASScanResult (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    openvas_scan_id INTEGER NOT NULL,
    vulnerability_id INTEGER NOT NULL,
    host_id INTEGER NOT NULL,
    
    -- Información específica del puerto/servicio
    port VARCHAR(20),
    protocol VARCHAR(10),
    detected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (openvas_scan_id) REFERENCES OpenVASScan (id) ON DELETE CASCADE,
    FOREIGN KEY (vulnerability_id) REFERENCES OpenVASVulnerability (id),
    FOREIGN KEY (host_id) REFERENCES Host (id),              
    
    UNIQUE KEY unique_detection (openvas_scan_id, vulnerability_id, host_id, port),
    INDEX idx_scan_id (openvas_scan_id),
    INDEX idx_vuln_id (vulnerability_id),
    INDEX idx_host_id (host_id)
);

INSERT INTO Rol (name, description, hierarchy_level)
VALUES 
	("ROOT_ACCOUNT", "Rol indispensable para el funcionamiento de la jerarquía", 0), 
    ("BASIC_ACCOUNT", "Rol con los permisos mínimos para usar la APP", 5);

INSERT INTO Person (first_name, last_name, alias, created_at)
VALUES ("Gabriel", "Musteata", "artexian", curdate());

INSERT INTO User (username, password_hash, email, password_salt, person_id, rol_id)
VALUES ("root", "683ae8fa196c380db02e5d97435c6981a591693d1b695f23e769500c046c2f6a", "gmiganescu@gmail.com", "c167837c1c2a860031d861164d69bd79", 1, 1);

SELECT *
FROM Person AS P
	JOIN User AS U ON P.id = U.person_id;
    
SELECT *
FROM AccessToken;
