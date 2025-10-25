CREATE TABLE `Persona` (
  `id` integer PRIMARY KEY,
  `nombre` varchar(255) NOT NULL,
  `apellido` varhcar NOT NULL,
  `fechaAlta` datetime NOT NULL
);

CREATE TABLE `Usuario` (
  `id` integer PRIMARY KEY,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `idPersona` integer NOT NULL
);

CREATE TABLE `Escaneo` (
  `id` integer PRIMARY KEY,
  `objetivo` varchar(255) NOT NULL,
  `fechaInicio` datetime NOT NULL,
  `idUsuario` integer NOT NULL
);

CREATE TABLE `EscaneoTerminado` (
  `id` integer PRIMARY KEY,
  `fechaFin` datetime NOT NULL
);

CREATE TABLE `EscaneoNmap` (
  `id` integer PRIMARY KEY
);

CREATE TABLE `PuertoObjetivo` (
  `idPuerto` integer,
  `idEscaneo` integer,
  PRIMARY KEY (`idPuerto`, `idEscaneo`)
);

CREATE TABLE `PuertoAbierto` (
  `idPuerto` integer,
  `idEscaneo` integer,
  `motivo` varchar(255) NOT NULL,
  PRIMARY KEY (`idPuerto`, `idEscaneo`)
);

CREATE TABLE `Puerto` (
  `id` integer PRIMARY KEY,
  `protocolo` varchar(255) UNIQUE NOT NULL
);

CREATE TABLE `EscaneoNikto` (
  `id` integer PRIMARY KEY
);

CREATE TABLE `IncidenciaEscaneo` (
  `idEscaneo` integer,
  `idIncidencia` integer,
  PRIMARY KEY (`idEscaneo`, `idIncidencia`)
);

CREATE TABLE `IncidenciaNikto` (
  `id` integer PRIMARY KEY,
  `idEscaneo` integer NOT NULL
);

CREATE TABLE `EscaneoOpenVAS` (
  `id` integer PRIMARY KEY
);

ALTER TABLE `Usuario` ADD FOREIGN KEY (`idPersona`) REFERENCES `Persona` (`id`);

ALTER TABLE `Escaneo` ADD FOREIGN KEY (`idUsuario`) REFERENCES `Persona` (`id`);

ALTER TABLE `EscaneoTerminado` ADD FOREIGN KEY (`id`) REFERENCES `Escaneo` (`id`);

ALTER TABLE `EscaneoNmap` ADD FOREIGN KEY (`id`) REFERENCES `Escaneo` (`id`);

ALTER TABLE `PuertoObjetivo` ADD FOREIGN KEY (`idPuerto`) REFERENCES `Puerto` (`id`);

ALTER TABLE `PuertoObjetivo` ADD FOREIGN KEY (`idEscaneo`) REFERENCES `EscaneoNmap` (`id`);

ALTER TABLE `PuertoAbierto` ADD FOREIGN KEY (`idPuerto`) REFERENCES `Puerto` (`id`);

ALTER TABLE `PuertoAbierto` ADD FOREIGN KEY (`idEscaneo`) REFERENCES `EscaneoNmap` (`id`);

ALTER TABLE `EscaneoNikto` ADD FOREIGN KEY (`id`) REFERENCES `Escaneo` (`id`);

ALTER TABLE `IncidenciaEscaneo` ADD FOREIGN KEY (`idEscaneo`) REFERENCES `EscaneoNikto` (`id`);

ALTER TABLE `IncidenciaEscaneo` ADD FOREIGN KEY (`idIncidencia`) REFERENCES `IncidenciaNikto` (`id`);

ALTER TABLE `EscaneoOpenVAS` ADD FOREIGN KEY (`id`) REFERENCES `Escaneo` (`id`);
