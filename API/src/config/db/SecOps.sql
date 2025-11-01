DROP DATABASE IF EXISTS SecOps;
CREATE DATABASE IF NOT EXISTS SecOps;

USE SecOps;

CREATE TABLE `Persona` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `nombre` VARCHAR(64) NOT NULL,
  `apellido` VARCHAR(64) NOT NULL,
  `email` varchar(128) NOT NULL,
  `fechaAlta` DATETIME NOT NULL
);

CREATE TABLE `Usuario` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `username` VARCHAR(64) NOT NULL UNIQUE,
  `password` VARCHAR(128) NOT NULL,
  `idPersona` INTEGER NOT NULL,
  FOREIGN KEY (`idPersona`) REFERENCES `Persona` (`id`)
);

CREATE TABLE `Escaneo` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `objetivo` VARCHAR(255) NOT NULL,
  `fechaInicio` DATETIME NOT NULL,
  `idUsuario` INTEGER NOT NULL,
  FOREIGN KEY (`idUsuario`) REFERENCES `Usuario` (`id`)
);

CREATE TABLE `EscaneoTerminado` (
  `id` INTEGER PRIMARY KEY,
  `fechaFin` DATETIME NOT NULL,
  FOREIGN KEY (`id`) REFERENCES `Escaneo` (`id`)
);

CREATE TABLE `EscaneoNmap` (
  `id` INTEGER PRIMARY KEY,
  FOREIGN KEY (`id`) REFERENCES `Escaneo` (`id`)
);

CREATE TABLE `Puerto` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `protocolo` VARCHAR(255) UNIQUE NOT NULL
);


CREATE TABLE `PuertoObjetivo` (
  `idPuerto` INTEGER,
  `idEscaneo` INTEGER,
  PRIMARY KEY (`idPuerto`, `idEscaneo`),
  FOREIGN KEY (`idPuerto`) REFERENCES `Puerto` (`id`),
  FOREIGN KEY (`idEscaneo`) REFERENCES `EscaneoNmap` (`id`)
);


CREATE TABLE `PuertoAbierto` (
  `idPuerto` INTEGER,
  `idEscaneo` INTEGER,
  `motivo` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`idPuerto`, `idEscaneo`),
  FOREIGN KEY (`idPuerto`) REFERENCES `Puerto` (`id`),
  FOREIGN KEY (`idEscaneo`) REFERENCES `EscaneoNmap` (`id`)
);


CREATE TABLE `EscaneoNikto` (
  `id` INTEGER PRIMARY KEY,
  FOREIGN KEY (`id`) REFERENCES `Escaneo` (`id`)
);


CREATE TABLE `IncidenciaNikto` (
  `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
  `idEscaneo` INTEGER NOT NULL,
  FOREIGN KEY (`idEscaneo`) REFERENCES `EscaneoNikto` (`id`)
);


CREATE TABLE `IncidenciaEscaneo` (
  `idEscaneo` INTEGER,
  `idIncidencia` INTEGER,
  PRIMARY KEY (`idEscaneo`, `idIncidencia`),
  FOREIGN KEY (`idEscaneo`) REFERENCES `EscaneoNikto` (`id`),
  FOREIGN KEY (`idIncidencia`) REFERENCES `IncidenciaNikto` (`id`)
);

CREATE TABLE `EscaneoOpenVAS` (
  `id` INTEGER PRIMARY KEY,
  FOREIGN KEY (`id`) REFERENCES `Escaneo` (`id`)
);
