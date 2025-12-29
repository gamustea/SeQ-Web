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

CREATE TABLE Scan (
	`id` INTEGER PRIMARY KEY AUTO_INCREMENT,
	`target` VARCHAR(255) NOT NULL,
	`started_at` DATETIME NOT NULL,
    `status` VARCHAR(20) NOT NULL DEFAULT 'pending',
	`user_id` INTEGER NOT NULL,
	`scan_type` VARCHAR(50),
    frecuent BOOLEAN NOT NULL DEFAULT false,
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

CREATE TABLE `OpenVASScan` (
  `id` INT NOT NULL,
  `openvas_task_id` VARCHAR(64) NULL,
  `openvas_report_id` VARCHAR(64) NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_openvas_scan_id`
    FOREIGN KEY (`id`) REFERENCES `Scan` (`id`)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- “Incidentes” reutilizables estilo NiktoIncident (propuesto)
CREATE TABLE `OpenVASVulnerability` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `nvt_oid` VARCHAR(64) NULL,
  `name` VARCHAR(512) NOT NULL,
  `severity` VARCHAR(32) NULL,
  `host` VARCHAR(255) NULL,
  `port` VARCHAR(32) NULL,
  `description` MEDIUMTEXT NULL,
  `solution` MEDIUMTEXT NULL,
  `references` MEDIUMTEXT NULL,
  `discovered_at` DATETIME NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_openvasvuln_nvt` (`nvt_oid`),
  KEY `idx_openvasvuln_host_port` (`host`, `port`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla many-to-many (equivalente a ScanIncident en Nikto) [file:2]
CREATE TABLE `OpenVASScanVulnerability` (
  `openvas_scan_id` INT NOT NULL,
  `openvas_vulnerability_id` INT NOT NULL,
  PRIMARY KEY (`openvas_scan_id`, `openvas_vulnerability_id`),
  CONSTRAINT `fk_osv_scan`
    FOREIGN KEY (`openvas_scan_id`) REFERENCES `OpenVASScan` (`id`)
    ON DELETE CASCADE,
  CONSTRAINT `fk_osv_vuln`
    FOREIGN KEY (`openvas_vulnerability_id`) REFERENCES `OpenVASVulnerability` (`id`)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

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

INSERT INTO Rol (name, description, hierarchy_level)
VALUES 
	("ROOT_ACCOUNT", "Rol indispensable para el funcionamiento de la jerarquía", 0), 
    ("BASIC_ACCOUNT", "Rol con los permisos mínimos para usar la APP", 5);

INSERT INTO Person (first_name, last_name, alias, created_at)
VALUES ("Gabriel", "Musteata", "artexian" curdate());

INSERT INTO User (username, password_hash, email, password_salt, person_id, rol_id)
VALUES ("root", "683ae8fa196c380db02e5d97435c6981a591693d1b695f23e769500c046c2f6a", "gmiganescu@gmail.com", "c167837c1c2a860031d861164d69bd79", 1, 1);
