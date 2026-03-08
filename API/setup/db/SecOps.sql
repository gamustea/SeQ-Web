DROP DATABASE IF EXISTS SeQ;
CREATE DATABASE IF NOT EXISTS SeQ;

USE SeQ;

CREATE TABLE `Person` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `first_name` VARCHAR(64) NOT NULL,
  `last_name` VARCHAR(64) NOT NULL,
  `alias` VARCHAR(64) UNIQUE NOT NULL,
  `created_at` DATETIME NOT NULL
);

CREATE TABLE `Rol` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `name` VARCHAR(32) UNIQUE NOT NULL,
  `hierarchy_level` INTEGER NOT NULL,
  `description` VARCHAR(128)
);

CREATE TABLE `User` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `username` VARCHAR(64) UNIQUE NOT NULL,
  `password_hash` VARCHAR(128) NOT NULL,
  `password_salt` varchar(128) NOT NULL,
  `email` VARCHAR(128) UNIQUE NOT NULL,
  `person_id` INTEGER NOT NULL,
  `rol_id` INTEGER NOT NULL
);

CREATE TABLE `Host` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `hostname` VARCHAR(64) UNIQUE NOT NULL,
  `ip_address` VARCHAR(15) NOT NULL,
  `mac_address` VARCHAR(17),
  `vendor` VARCHAR(64)
);

CREATE TABLE `Scan` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `target` VARCHAR(255) NOT NULL,
  `started_at` DATETIME NOT NULL,
  `finished_at` DATETIME,
  `status` VARCHAR(20) NOT NULL DEFAULT 'pending',
  `user_id` INTEGER NOT NULL,
  `scan_type` VARCHAR(50),
  `frecuent` BOOLEAN NOT NULL DEFAULT false,
  `host_id` INTEGER
);

CREATE TABLE `NmapScan` (
  `id` INTEGER PRIMARY KEY
);

CREATE TABLE `Port` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `protocol` VARCHAR(255) UNIQUE
);

CREATE TABLE `TargetPort` (
  `port_id` INTEGER,
  `nmap_scan_id` INTEGER,
  PRIMARY KEY (`port_id`, `nmap_scan_id`)
);

CREATE TABLE `OpenPort` (
  `port_id` INTEGER,
  `nmap_scan_id` INTEGER,
  `reason` VARCHAR(255) NOT NULL,
  `product` Varchar(255),
  `version` VARCHAR(64),
  `given_use` VARCHAR(255),
  PRIMARY KEY (`port_id`, `nmap_scan_id`)
);

CREATE TABLE `NiktoScan` (
  `id` INTEGER PRIMARY KEY
);

CREATE TABLE `NiktoIncident` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `osvdb_id` VARCHAR(20),
  `method` VARCHAR(10),
  `url` VARCHAR(512) NOT NULL,
  `description` TEXT NOT NULL,
  `severity` VARCHAR(20),
  `port` INTEGER,
  `references` TEXT,
  `discovered_at` DATETIME NOT NULL
);

CREATE TABLE `ScanIncident` (
  `nikto_scan_id` INTEGER,
  `nikto_incident_id` INTEGER,
  PRIMARY KEY (`nikto_scan_id`, `nikto_incident_id`)
);

CREATE TABLE `AccessToken` (
  `id` INT PRIMARY KEY AUTO_INCREMENT,
  `token` VARCHAR(512) UNIQUE NOT NULL,
  `user_id` INT NOT NULL,
  `expires_at` DATETIME NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT (CURRENT_TIMESTAMP),
  `revoked` TINYINT DEFAULT 0
);

CREATE TABLE `RefreshToken` (
  `id` INT PRIMARY KEY AUTO_INCREMENT,
  `token` VARCHAR(512) UNIQUE NOT NULL,
  `user_id` INT NOT NULL,
  `expires_at` DATETIME NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT (CURRENT_TIMESTAMP),
  `revoked` TINYINT DEFAULT 0
);

CREATE TABLE `OpenVASScan` (
  `id` INTEGER PRIMARY KEY,
  `task_id` VARCHAR(255) NOT NULL,
  `report_id` VARCHAR(255) NOT NULL,
  `scan_config_name` VARCHAR(255),
  `scanner_name` VARCHAR(255)
);

CREATE TABLE `OpenVASVulnerability` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `nvt_oid` VARCHAR(255) UNIQUE NOT NULL,
  `name` TEXT NOT NULL,
  `severity_score` DECIMAL(3,1),
  `severity_class` VARCHAR(20),
  `cvss_base_score` DECIMAL(3,1),
  `cvss_vector` VARCHAR(255),
  `cve_ids` TEXT,
  `cert_refs` TEXT,
  `bugtraq_ids` TEXT,
  `other_refs` TEXT,
  `summary` TEXT,
  `description` TEXT,
  `impact` TEXT,
  `insight` TEXT,
  `affected_software` TEXT,
  `solution_type` VARCHAR(50),
  `solution` TEXT,
  `qod_value` INTEGER,
  `qod_type` VARCHAR(100),
  `family` VARCHAR(255),
  `category` VARCHAR(255),
  `created_at` DATETIME NOT NULL DEFAULT (CURRENT_TIMESTAMP),
  `updated_at` DATETIME DEFAULT (CURRENT_TIMESTAMP)
);

CREATE TABLE `OpenVASScanResult` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `host_id` INTEGER NOT NULL,
  `openvas_scan_id` INTEGER NOT NULL,
  `vulnerability_id` INTEGER NOT NULL,
  `detected_at` DATETIME NOT NULL DEFAULT (CURRENT_TIMESTAMP)
);

CREATE TABLE `Vault` (
  `id` integer PRIMARY KEY AUTO_INCREMENT,
  `user_id` integer NOT NULL,
  `is_recovery` boolean NOT NULL DEFAULT false,
  `checker` varchar(512) NOT NULL,
  `vault_key` varchar(512) NOT NULL,
  `transformation` varchar(64) NOT NULL,
  `kdf` varchar(64) NOT NULL,
  `kdf_iterations` integer NOT NULL,
  `kdf_memory` integer NOT NULL,
  `kdf_parallelism` integer NOT NULL,
  `salt` varchar(128) NOT NULL
);

CREATE TABLE `Storable` (
  `id` integer PRIMARY KEY AUTO_INCREMENT,
  `type` varchar(16) NOT NULL,
  `internal_id` varchar(128),
  `title` varchar(128),
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  `vault_id` integer NOT NULL
);

CREATE TABLE `Account` (
  `id` integer PRIMARY KEY,
  `username` varchar(512) NOT NULL,
  `domain` varchar(512) NOT NULL,
  `password` varchar(512) NOT NULL
);

CREATE TABLE `CreditCard` (
  `id` integer PRIMARY KEY,
  `cardholder_name` varchar(512) NOT NULL,
  `card_number` varchar(512) NOT NULL,
  `expiration_date` varchar(512) NOT NULL,
  `postal_code` varchar(512) NOT NULL,
  `cvv` varchar(512) NOT NULL
);

CREATE TABLE `Topic` (
  `id`    INT         NOT NULL AUTO_INCREMENT,
  `title` VARCHAR(64) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `AegisDocument` (
  `id`           INT          NOT NULL AUTO_INCREMENT,
  `title`        VARCHAR(64)  NOT NULL,
  `filename`     VARCHAR(128) NOT NULL,
  `status`		 VARCHAR(32)  NOT NULL DEFAULT 'pending',
  `generated_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `topic_id`     INT          NOT NULL,
  `user_id`      INT          NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_aegis_document_filename` (`filename`),
  KEY `ix_aegis_document_topic_id` (`topic_id`),
  KEY `ix_aegis_document_user_id`  (`user_id`),
  CONSTRAINT `fk_aegis_document_topic`
    FOREIGN KEY (`topic_id`) REFERENCES `Topic` (`id`)
    ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT `fk_aegis_document_user`
    FOREIGN KEY (`user_id`) REFERENCES `User` (`id`)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


CREATE INDEX `idx_token` ON `AccessToken` (`token`);

CREATE INDEX `idx_user` ON `AccessToken` (`user_id`);

CREATE INDEX `idx_token` ON `RefreshToken` (`token`);

CREATE INDEX `idx_user` ON `RefreshToken` (`user_id`);

CREATE UNIQUE INDEX `OpenVASScan_index_4` ON `OpenVASScan` (`task_id`, `report_id`);

CREATE INDEX `idx_nvt_oid` ON `OpenVASVulnerability` (`nvt_oid`);

CREATE INDEX `idx_severity_class` ON `OpenVASVulnerability` (`severity_class`);

CREATE INDEX `idx_scan_id` ON `OpenVASScanResult` (`openvas_scan_id`);

CREATE INDEX `idx_vuln_id` ON `OpenVASScanResult` (`vulnerability_id`);

CREATE INDEX `idx_host_id` ON `OpenVASScanResult` (`host_id`);

CREATE UNIQUE INDEX `Vault_index_10` ON `Vault` (`user_id`, `is_recovery`);

CREATE UNIQUE INDEX `Storable_index_11` ON `Storable` (`vault_id`, `internal_id`);

CREATE UNIQUE INDEX `Storable_index_12` ON `Storable` (`title`, `vault_id`);

ALTER TABLE `Storable` ADD FOREIGN KEY (`vault_id`) REFERENCES `Vault` (`id`);

ALTER TABLE `Account` ADD FOREIGN KEY (`id`) REFERENCES `Storable` (`id`);

ALTER TABLE `CreditCard` ADD FOREIGN KEY (`id`) REFERENCES `Storable` (`id`);

ALTER TABLE `Vault` ADD FOREIGN KEY (`user_id`) REFERENCES `User` (`id`);

ALTER TABLE `User` ADD FOREIGN KEY (`rol_id`) REFERENCES `Rol` (`id`);

ALTER TABLE `User` ADD FOREIGN KEY (`person_id`) REFERENCES `Person` (`id`);

ALTER TABLE `Scan` ADD FOREIGN KEY (`user_id`) REFERENCES `User` (`id`);

ALTER TABLE `Scan` ADD FOREIGN KEY (`host_id`) REFERENCES `Host` (`id`);

ALTER TABLE `NmapScan` ADD FOREIGN KEY (`id`) REFERENCES `Scan` (`id`);

ALTER TABLE `TargetPort` ADD FOREIGN KEY (`port_id`) REFERENCES `Port` (`id`);

ALTER TABLE `TargetPort` ADD FOREIGN KEY (`nmap_scan_id`) REFERENCES `NmapScan` (`id`);

ALTER TABLE `OpenPort` ADD FOREIGN KEY (`port_id`) REFERENCES `Port` (`id`);

ALTER TABLE `OpenPort` ADD FOREIGN KEY (`nmap_scan_id`) REFERENCES `NmapScan` (`id`);

ALTER TABLE `NiktoScan` ADD FOREIGN KEY (`id`) REFERENCES `Scan` (`id`);

ALTER TABLE `ScanIncident` ADD FOREIGN KEY (`nikto_scan_id`) REFERENCES `NiktoScan` (`id`);

ALTER TABLE `ScanIncident` ADD FOREIGN KEY (`nikto_incident_id`) REFERENCES `NiktoIncident` (`id`);

ALTER TABLE `AccessToken` ADD FOREIGN KEY (`user_id`) REFERENCES `User` (`id`) ON DELETE CASCADE;

ALTER TABLE `RefreshToken` ADD FOREIGN KEY (`user_id`) REFERENCES `User` (`id`) ON DELETE CASCADE;

ALTER TABLE `OpenVASScan` ADD FOREIGN KEY (`id`) REFERENCES `Scan` (`id`);

ALTER TABLE `OpenVASScanResult` ADD FOREIGN KEY (`openvas_scan_id`) REFERENCES `OpenVASScan` (`id`) ON DELETE CASCADE;

ALTER TABLE `OpenVASScanResult` ADD FOREIGN KEY (`vulnerability_id`) REFERENCES `OpenVASVulnerability` (`id`);

ALTER TABLE `OpenVASScanResult` ADD FOREIGN KEY (`host_id`) REFERENCES `Host` (`id`);

INSERT INTO Rol (name, description, hierarchy_level)
VALUES 
	("ROOT_ACCOUNT", "Rol indispensable para el funcionamiento de la jerarquía", 0), 
    ("BASIC_ACCOUNT", "Rol con los permisos mínimos para usar la APP", 5);

INSERT INTO Person (first_name, last_name, alias, created_at)
VALUES ("Gabriel", "Musteata", "artexian", curdate());

INSERT INTO User (username, password_hash, email, password_salt, person_id, rol_id)
VALUES ("root", "683ae8fa196c380db02e5d97435c6981a591693d1b695f23e769500c046c2f6a", "gmiganescu@gmail.com", "c167837c1c2a860031d861164d69bd79", 1, 1);

INSERT INTO `Topic` (`title`) VALUES

-- Ingeniería Social
('Phishing y suplantación de identidad'),
('Spear phishing: ataques dirigidos'),
('Smishing: fraude por SMS'),
('Vishing: fraude por llamada telefónica'),
('Pretexting: manipulación por contexto falso'),
('Baiting: señuelos físicos y digitales'),
('Quid pro quo: intercambio fraudulento'),

-- Contraseñas y Autenticación
('Contraseñas robustas: cómo crearlas'),
('Gestores de contraseñas corporativos'),
('Autenticación de doble factor (2FA)'),
('Riesgos de reutilizar contraseñas'),
('Ataques de fuerza bruta y diccionario'),
('Passkeys: el futuro sin contraseñas'),

-- Correo Electrónico
('Uso seguro del correo corporativo'),
('Cómo identificar un correo fraudulento'),
('Riesgos de archivos adjuntos maliciosos'),
('Email spoofing: correos falsificados'),
('BEC: fraude al CEO por correo'),

-- Malware
('Ransomware: secuestro de datos'),
('Troyanos: software disfrazado'),
('Spyware: espionaje silencioso'),
('Adware y PUPs: software no deseado'),
('Keyloggers: robo de pulsaciones'),
('Rootkits: control oculto del sistema'),
('Fileless malware: ataques sin fichero'),

-- Navegación y Web
('Navegación segura por Internet'),
('Riesgos de las extensiones de navegador'),
('Verificación de URLs y certificados HTTPS'),
('Descargas desde fuentes no confiables'),
('Drive-by download: infección al navegar'),
('Inyección SQL: riesgo en formularios web'),
('Cross-Site Scripting (XSS)'),

-- Redes y Conectividad
('Riesgos de redes Wi-Fi públicas'),
('VPN: qué es y cuándo usarla'),
('Ataques Man-in-the-Middle (MitM)'),
('Seguridad en redes domésticas'),
('Riesgos del Bluetooth activo'),
('DNS spoofing: redirección maliciosa'),

-- Dispositivos y Endpoints
('Actualización de software y parches'),
('Seguridad en dispositivos móviles'),
('Riesgos del BYOD en la empresa'),
('Bloqueo de pantalla y sesiones'),
('Cifrado de disco en portátiles'),
('Seguridad en impresoras y periféricos'),
('Riesgos de los dispositivos USB'),

-- Datos e Información
('Borrado seguro de información'),
('Metadatos ocultos en documentos'),
('Clasificación de la información'),
('Política de escritorio limpio'),
('Fugas de información no intencionadas'),
('Protección de datos personales (RGPD)'),

-- Copias de Seguridad
('Copias de seguridad: por qué y cómo'),
('Estrategia 3-2-1 de backups'),
('Recuperación ante desastres'),
('Verificación de restauraciones'),

-- Cloud y Servicios Online
('Seguridad en servicios en la nube'),
('Riesgos de compartir documentos en cloud'),
('Shadow IT: apps no autorizadas'),
('Configuraciones inseguras en cloud'),
('OAuth y permisos de aplicaciones terceras'),

-- Trabajo Remoto
('Teletrabajo seguro'),
('Riesgos del acceso remoto (RDP)'),
('Seguridad en videoconferencias'),
('Entornos de trabajo híbrido'),

-- Amenazas Avanzadas
('APT: amenazas persistentes avanzadas'),
('Ataques a la cadena de suministro'),
('Zero-day: vulnerabilidades sin parche'),
('Lateral movement: movimiento en red interna'),
('Exfiltración de datos corporativos'),

-- Concienciación General
('Ingeniería social en redes sociales'),
('Sobrexposición en redes sociales'),
('Fraude en compras online'),
('Ciberseguridad en vacaciones'),
('Reporte de incidentes de seguridad'),
('El factor humano en ciberseguridad'),
('Cultura de seguridad en la empresa');


SELECT *
FROM Vault AS V
	JOIN Storable AS S ON V.id = S.vault_id
    JOIN CreditCard AS CC ON CC.id = S.id;
    
SELECT *
FROM AegisDocument;


