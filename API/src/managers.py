import threading
from datetime import datetime
from typing import Dict, Optional, List
from abc import abstractmethod, ABC
from src.persistence import (
    ScanDBManager,
    NmapDBManager,
    DBManager,
    NiktoDBManager,
)
from src.tasks import NmapScanTask, NiktoScanTask, _Task
from src.model import NmapScan, User, NiktoScan, NiktoIncident, Scan
from src.misc.conversion import JSONManager
from src.misc.logging import SecOpsLogger

# Configurar logger
logger_instance = SecOpsLogger(name="ScanManager")
logger = logger_instance.get_logger()


def assign_severity_to_nikto_incident(incident):
    """
    Asigna la severidad a un incidente de Nikto basándose en patrones de vulnerabilidad.

    Modifica el objeto incident directamente asignando el atributo 'severity'.

    Args:
        incident: Objeto NiktoIncident con atributos:
                  - description (str): Descripción del hallazgo
                  - method (str): Método HTTP utilizado
                  - url (str): URL afectada
                  - osvdb_id (str/int): ID de OSVDB

    Severidades asignadas:
        - CRITICAL: Exposición de archivos sensibles, credenciales, configuraciones críticas
        - HIGH: Vulnerabilidades de ejecución remota, autenticación débil, SSL/TLS débil
        - MEDIUM: Headers de seguridad faltantes, listado de directorios, información sensible
        - LOW: Información del servidor, métodos HTTP permitidos, páginas por defecto
        - INFO: Hallazgos informativos sin riesgo directo
    """

    # Convertir descripción a minúsculas para análisis
    desc = incident.description.lower() if incident.description else ""
    url = incident.url.lower() if incident.url else ""
    method = incident.method.upper() if incident.method else ""

    # ========================================================================
    # CRITICAL - Exposición de archivos sensibles y configuraciones críticas
    # ========================================================================
    critical_patterns = [
        ".env",  # Variables de entorno (credenciales, API keys)
        "env.production",
        "env.local",
        ".git/",  # Repositorio Git expuesto
        ".git/config",
        "git/head",
        "phpinfo",  # Información completa de PHP
        "config.php",  # Archivos de configuración
        "database.yml",
        "wp-config.php",  # WordPress config
        "web.config",  # IIS config
        ".sql",  # Dumps de base de datos
        "backup.sql",
        "dump.sql",
        "passwd",  # Archivo de contraseñas Unix
        "shadow",
        "credentials",
        "private_key",
        "id_rsa",  # Claves SSH
        "config.bak",  # Backups de configuración
        "database.bak",
        "shell",  # Shells web
        "webshell",
        "backdoor",
        "remote code execution",  # RCE
        "arbitrary code",
        "command injection",
        "sql injection",  # SQLi crítico
        "unrestricted file upload",
    ]

    for pattern in critical_patterns:
        if pattern in desc or pattern in url:
            incident.severity = "CRITICAL"
            return

    # ========================================================================
    # HIGH - Vulnerabilidades explotables y debilidades de seguridad serias
    # ========================================================================
    high_patterns = [
        "outdated",  # Software desactualizado
        "vulnerable version",
        "known vulnerability",
        "cve-",  # Referencias CVE
        "xss",  # Cross-Site Scripting
        "cross site scripting",
        "cross-site scripting",
        "csrf",  # Cross-Site Request Forgery
        "authentication bypass",
        "authorization bypass",
        "privilege escalation",
        "directory traversal",
        "path traversal",
        "../",
        "local file inclusion",
        "remote file inclusion",
        "lfi",
        "rfi",
        "weak ssl",  # SSL/TLS débil
        "weak tls",
        "ssl v2",
        "ssl v3",
        "sslv2",
        "sslv3",
        "poodle",
        "heartbleed",
        "shellshock",
        "default password",  # Credenciales por defecto
        "default credential",
        "admin/admin",
        "weak cipher",
        "insecure cipher",
        "null cipher",
        "export cipher",
    ]

    # Métodos HTTP peligrosos
    dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]

    for pattern in high_patterns:
        if pattern in desc or pattern in url:
            incident.severity = "HIGH"
            return

    if method in dangerous_methods and "allowed" in desc:
        incident.severity = "HIGH"
        return

    # ========================================================================
    # MEDIUM - Problemas de configuración y debilidades moderadas
    # ========================================================================
    medium_patterns = [
        "directory indexing",  # Listado de directorios
        "directory listing",
        "indexes",
        "missing security header",  # Headers de seguridad faltantes
        "x-frame-options",
        "x-content-type-options",
        "content-security-policy",
        "strict-transport-security",
        "x-xss-protection",
        "clickjacking",
        "information disclosure",  # Divulgación de información
        "information leakage",
        "stack trace",
        "error message",
        "debug mode",
        "verbose error",
        "source code disclosure",
        "path disclosure",
        "version disclosure",
        "session fixation",
        "weak session",
        "cookie without",  # Cookies inseguras
        "cookie httponly",
        "cookie secure",
        "unencrypted",
        "http basic auth",  # Autenticación básica sin HTTPS
        "weak authentication",
        "robots.txt",  # Archivos que revelan estructura
        "sitemap.xml",
        "cors misconfiguration",
        "open redirect",
        "server-status",  # Páginas de estado del servidor
        "server-info",
        "admin panel",  # Paneles de administración expuestos
        "login panel",
        "phpmyadmin",
        "adminer",
    ]

    for pattern in medium_patterns:
        if pattern in desc or pattern in url:
            incident.severity = "MEDIUM"
            return

    # ========================================================================
    # LOW - Problemas menores y mejores prácticas
    # ========================================================================
    low_patterns = [
        "server banner",  # Banners del servidor
        "server header",
        "x-powered-by",
        "server version",
        "apache/",
        "nginx/",
        "microsoft-iis",
        "options method",  # Métodos HTTP informativos
        "head method",
        "allowed http methods",
        "default page",  # Páginas por defecto
        "default installation",
        "test page",
        "welcome page",
        "it works",
        "uncommon header",  # Headers no estándar
        "unusual header",
        "missing header",  # Headers recomendados pero no críticos
        "cache control",
        "pragma",
        "expires",
        "retrieved x-powered-by",  # Detección de tecnología
        "retrieved server",
        "ip address",  # Divulgación de IP interna
        "internal ip",
        "retrieved via",
    ]

    for pattern in low_patterns:
        if pattern in desc or pattern in url:
            incident.severity = "LOW"
            return

    # ========================================================================
    # INFO - Hallazgos informativos sin riesgo directo
    # ========================================================================
    info_patterns = [
        "the site uses",
        "appears to be",
        "may be",
        "possibly",
        "cookie created",
        "retrieved",
        "hostname resolves",
        "scan completed",
        "target ip",
        "end time",
        "start time",
    ]

    for pattern in info_patterns:
        if pattern in desc:
            incident.severity = "INFO"
            return

    # ========================================================================
    # DEFAULT - Si no coincide con ningún patrón
    # ========================================================================
    # Por defecto, asignar MEDIUM como nivel conservador
    incident.severity = "MEDIUM"


class _ScanManager(ABC):
    running_tasks: Dict[int, _Task]
    active_user: User

    def __init__(self, user: User):
        self.running_tasks = {}
        self.active_user = user
        self.thread = None
        logger.info(
            f"ScanManager inicializado para usuario: {user.id if hasattr(user, 'id') else 'unknown'}"
        )

    def get_running_task_progress(self, id: int) -> Optional[int]:
        if id in self.running_tasks:
            progress = self.running_tasks[id].progress
            logger.debug(f"Progreso de tarea {id}: {progress}%")
            return progress
        logger.warning(f"Tarea {id} no encontrada en tareas en ejecución")
        return None

    @abstractmethod
    def get_scans_for_user(self) -> List:
        pass


class NmapScanManager(_ScanManager):
    def __init__(self, user: User):
        super().__init__(user)
        self.dbmanager = NmapDBManager()
        logger.info("NmapScanManager inicializado correctamente")

    def _do_scan_and_save(
        self,
        target_host: str,
        target_ports: str,
        nmap_scan_model: NmapScan,
        timeout: int = 20,
    ) -> None:
        try:
            logger.info(
                f"Iniciando escaneo Nmap: target={target_host}, ports={target_ports}, timeout={timeout}"
            )

            task = NmapScanTask(target_host, target_ports, timeout=timeout)
            self.running_tasks[nmap_scan_model.id] = task  # type: ignore

            logger.info(f"Ejecutando escaneo Nmap con ID {nmap_scan_model.id}")
            task.scan()
            task.wait()

            logger.info(
                f"Escaneo Nmap {nmap_scan_model.id} completado, procesando resultados"
            )
            results = JSONManager.convert_json_to_individual_nmap_data(task.results, nmap_scan_model)  # type: ignore
            nmap_scan_model.results = results

            # Procesar puertos encontrados
            ports_count = len(results["ports"])
            logger.info(
                f"Procesando {ports_count} puertos del escaneo {nmap_scan_model.id}"
            )

            for port in results["ports"]:
                port_model = self.dbmanager.get_or_create_port(port[0])
                self.dbmanager.add_target_port(nmap_scan_model, port_model)
                self.dbmanager.add_open_port(nmap_scan_model, port_model, port[2])

            logger.info(
                f"Escaneo Nmap {nmap_scan_model.id} guardado exitosamente con {ports_count} puertos"
            )

        except Exception as e:
            logger.error(
                f"Error en escaneo Nmap {nmap_scan_model.id}: {str(e)}", exc_info=True
            )
            raise

    def run_task(self, target_host: str, target_ports: str, timeout: int = 20):
        try:
            if target_host in self.running_tasks:
                logger.warning(
                    f"Intento de escaneo duplicado para target: {target_host}"
                )
                raise Exception(f"A scan is already running for target {target_host}")

            logger.info(f"Creando nuevo escaneo Nmap para {target_host}")
            nmap_scan_model = NmapScan(target=target_host, user=self.active_user)
            nmap_scan_model.started_at = datetime.now() # type: ignore
            self.dbmanager.create_nmap_scan(nmap_scan_model)

            logger.info(f"Escaneo Nmap {nmap_scan_model.id} creado, iniciando thread")
            self.thread = threading.Thread(
                target=self._do_scan_and_save,
                args=(target_host, target_ports, nmap_scan_model),
            )
            self.thread.start()

            logger.info(
                f"Thread de escaneo Nmap {nmap_scan_model.id} iniciado exitosamente"
            )
            return nmap_scan_model.id

        except Exception as e:
            logger.error(f"Error al iniciar tarea Nmap: {str(e)}", exc_info=True)
            raise

    def get_scans_for_user(self) -> List:
        try:
            logger.info(f"Obteniendo escaneos Nmap para usuario {self.active_user.id}")
            scans = self.dbmanager.get_nmap_scans_by_user(self.active_user.id)
            logger.info(
                f"Se obtuvieron {len(scans)} escaneos Nmap para usuario {self.active_user.id}"
            )
            return scans
        except Exception as e:
            logger.error(
                f"Error al obtener escaneos Nmap para usuario {self.active_user.id}: {str(e)}",
                exc_info=True,
            )
            raise

    def get_scan_by_id(self, id: int) -> Scan:
        try:
            logger.info(f"Obteniendo escaneo Nmap con ID: {id}")
            scan = self.dbmanager.get_scan_by_id(id)
            if scan:
                logger.info(f"Escaneo Nmap {id} obtenido exitosamente")
            else:
                logger.warning(f"Escaneo Nmap {id} no encontrado")
            return scan
        except Exception as e:
            logger.error(f"Error al obtener escaneo Nmap {id}: {str(e)}", exc_info=True)
            raise


class NiktoScanManager(_ScanManager):
    def __init__(self, user: User):
        super().__init__(user)
        self.dbmanager = NiktoDBManager()
        logger.info("NiktoScanManager inicializado correctamente")

    def _do_scan_and_save(
        self, target_domain: str, nikto_scan_model: NiktoScan, timeout=20
    ) -> None:
        try:
            logger.info(
                f"Iniciando escaneo Nikto: target={target_domain}, timeout={timeout}"
            )

            task = NiktoScanTask(target_domain, timeout)
            self.running_tasks[nikto_scan_model.id] = task  # type: ignore

            logger.info(f"Ejecutando escaneo Nikto con ID {nikto_scan_model.id}")
            task.scan()
            task.wait()

            logger.info(
                f"Escaneo Nikto {nikto_scan_model.id} completado, procesando resultados"
            )
            results = JSONManager.convert_json_to_individual_nikto_data(task.results[-1])  # type: ignore
            task.results = results

            # Procesar incidentes encontrados
            incidents_count = len(results)
            logger.info(
                f"Procesando {incidents_count} incidentes del escaneo Nikto {nikto_scan_model.id}"
            )

            for result in results:
                description = result["description"]
                osvdbid = result["osvdbid"]
                method = result["method"]
                uri = result["uri"]

                incident = NiktoIncident()
                incident.description = description
                incident.osvdb_id = osvdbid
                incident.method = method
                incident.url = uri
                assign_severity_to_nikto_incident(incident)

                new_incident = self.dbmanager.get_or_create_nikto_incident(incident)  # type: ignore
                self.dbmanager.add_incident(nikto_scan_model, new_incident)

            logger.info(
                f"Escaneo Nikto {nikto_scan_model.id} guardado exitosamente con {incidents_count} incidentes"
            )

        except Exception as e:
            logger.error(
                f"Error en escaneo Nikto {nikto_scan_model.id}: {str(e)}", exc_info=True
            )
            raise

    def run_task(self, target_host: str, timeout: int = 60):
        try:
            if target_host in self.running_tasks:
                logger.warning(
                    f"Intento de escaneo Nikto duplicado para target: {target_host}"
                )
                raise Exception(f"A scan is already running for target {target_host}")

            logger.info(f"Creando nuevo escaneo Nikto para {target_host}")
            nikto_scan_model = NiktoScan(target=target_host, user=self.active_user)
            nikto_scan_model.started_at = datetime.now() # type: ignore
            self.dbmanager.create_nikto_scan(nikto_scan_model)

            logger.info(f"Escaneo Nikto {nikto_scan_model.id} creado, iniciando thread")
            self.thread = threading.Thread(
                target=self._do_scan_and_save, args=(target_host, nikto_scan_model)
            )
            self.thread.start()

            logger.info(
                f"Thread de escaneo Nikto {nikto_scan_model.id} iniciado exitosamente"
            )
            return nikto_scan_model.id

        except Exception as e:
            logger.error(f"Error al iniciar tarea Nikto: {str(e)}", exc_info=True)
            raise

    def get_scans_for_user(self) -> List:
        try:
            logger.info(f"Obteniendo escaneos Nikto para usuario {self.active_user.id}")
            scans = self.dbmanager.get_nikto_scans_by_user(self.active_user.id)
            logger.info(
                f"Se obtuvieron {len(scans)} escaneos Nikto para usuario {self.active_user.id}"
            )
            return scans
        except Exception as e:
            logger.error(
                f"Error al obtener escaneos Nikto para usuario {self.active_user.id}: {str(e)}",
                exc_info=True,
            )
            raise

    def get_scan_by_id(self, id: int) -> Scan:
        try:
            logger.info(f"Obteniendo escaneo Nikto con ID: {id}")
            scan = self.dbmanager.get_scan_by_id(id)
            if scan:
                logger.info(f"Escaneo Nikto {id} obtenido exitosamente")
            else:
                logger.warning(f"Escaneo Nikto {id} no encontrado")
            return scan
        except Exception as e:
            logger.error(
                f"Error al obtener escaneo Nikto {id}: {str(e)}", exc_info=True
            )
            raise
