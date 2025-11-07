DROP DATABASE IF EXISTS SecOps;

CREATE DATABASE IF NOT EXISTS SecOps;

USE SecOps;

CREATE TABLE `Person` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `first_name` VARCHAR(64) NOT NULL,
  `last_name` VARCHAR(64) NOT NULL,
  `email` varchar(128) NOT NULL,
  `created_at` DATETIME NOT NULL
);

CREATE TABLE `User` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `username` VARCHAR(64) NOT NULL UNIQUE,
  `password` VARCHAR(128) NOT NULL,
  `person_id` INTEGER NOT NULL,
  FOREIGN KEY (`person_id`) REFERENCES `Person` (`id`)
);

CREATE TABLE `Scan` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `target` VARCHAR(255) NOT NULL,
  `started_at` DATETIME NOT NULL,
  `user_id` INTEGER NOT NULL,
  `scan_type` varchar(64) NOT NULL, 
  FOREIGN KEY (`user_id`) REFERENCES `User` (`id`)
);

CREATE TABLE `FinishedScan` (
  `id` INTEGER PRIMARY KEY,
  `finished_at` DATETIME NOT NULL,
  FOREIGN KEY (`id`) REFERENCES `Scan` (`id`)
);

CREATE TABLE `NmapScan` (
  `id` INTEGER PRIMARY KEY,
  FOREIGN KEY (`id`) REFERENCES `Scan` (`id`)
);

CREATE TABLE `NiktoScan` (
  `id` INTEGER PRIMARY KEY,
  FOREIGN KEY (`id`) REFERENCES `Scan` (`id`)
);

CREATE TABLE `NiktoIncident` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `nikto_scan_id` INTEGER NOT NULL,
  FOREIGN KEY (`nikto_scan_id`) REFERENCES `NiktoScan` (`id`)
);

CREATE TABLE `ScanIncident` (
  `nikto_scan_id` INTEGER NOT NULL,
  `nikto_incident_id` INTEGER NOT NULL,
  PRIMARY KEY (`nikto_scan_id`, `nikto_incident_id`),
  FOREIGN KEY (`nikto_scan_id`) REFERENCES `NiktoScan` (`id`),
  FOREIGN KEY (`nikto_incident_id`) REFERENCES `NiktoIncident` (`id`)
);

CREATE TABLE `OpenVASScan` (
  `id` INTEGER PRIMARY KEY,
  FOREIGN KEY (`id`) REFERENCES `Scan` (`id`)
);

CREATE TABLE `Port` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `protocol` VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE `TargetPort` (
  `port_id` INTEGER NOT NULL,
  `nmap_scan_id` INTEGER NOT NULL,
  PRIMARY KEY (`port_id`, `nmap_scan_id`),
  FOREIGN KEY (`port_id`) REFERENCES `Port` (`id`),
  FOREIGN KEY (`nmap_scan_id`) REFERENCES `NmapScan` (`id`)
);

CREATE TABLE `OpenPort` (
  `port_id` INTEGER NOT NULL,
  `nmap_scan_id` INTEGER NOT NULL,
  `reason` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`port_id`, `nmap_scan_id`),
  FOREIGN KEY (`port_id`) REFERENCES `Port` (`id`),
  FOREIGN KEY (`nmap_scan_id`) REFERENCES `NmapScan` (`id`)
);

INSERT INTO Person VALUES 
	(1, "Gabriel", "Musteata", "gamustea@unirioja.es", "2025-11-06");
    
INSERT INTO User VALUES
	(1, "root", "root", 1);
    
SELECT *
FROM Person AS P
	JOIN User AS U ON U.person_id = P.id;

SELECT *
FROM NmapScan AS NS
	JOIN OpenPort AS OP ON NS.id = OP.nmap_scan_id
    JOIN Port AS P ON P.id = OP.port_id;