import threading

from datetime import datetime
from typing import Dict, Optional, List
from abc import abstractmethod, ABC

from src.persistence import (
    ScanDBManager,
    NmapDBManager,
    NiktoDBManager,
)

from src.logic.tasking.tasks import NmapScanTask, NiktoScanTask, _Task
from src.core.model import NmapScan, User, NiktoScan, NiktoIncident, Scan
from src.misc.conversion import JSONManager
from src.misc.logging import SecOpsLogger


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
        self.dbmanager = ScanDBManager()
        
        self.logger = SecOpsLogger(name="ScanManager").get_logger()
        self.logger.info(
            f"ScanManager inicializado para usuario: {user.id if hasattr(user, 'id') else 'unknown'}"
        )

    def get_running_task_progress(self, id: int) -> Optional[int]:
        if id in self.running_tasks:
            progress = self.running_tasks[id].progress
            self.logger.debug(f"Progreso de tarea {id}: {progress}%")
            return progress
        self.logger.warning(f"Tarea {id} no encontrada en tareas en ejecución")
        return None

    @abstractmethod
    def get_scans_for_user(self) -> List:
        pass

    def scan_is_finished(self, scan: Scan) -> bool:
        """Verifica si un escaneo ha finalizado."""
        try:
            if not self.dbmanager: # type: ignore
                self.logger.error("dbmanager no está inicializado")
                return False

            # SOLUCIÓN: Refrescar el objeto antes de usar su ID
            self.dbmanager.session.refresh(scan)
            
            return self.dbmanager.scan_is_finished(scan.id)  # type: ignore
        except Exception as e:
            self.logger.error(
                f"Error al verificar si el escaneo {scan.id} está terminado: {e}"
            )
            return False

    def scan_is_finished_by_id(self, scan_id: int) -> Optional[bool]:
        """
        Verifica si un escaneo ha finalizado usando solo su ID.
        
        Returns:
            True si está terminado
            False si no está terminado
            None si no existe
        """
        try:
            if not self.dbmanager: # type: ignore
                self.logger.error("dbmanager no está inicializado")
                return None

            # Verificar que el escaneo existe
            if not self.dbmanager.scan_exists(scan_id):
                self.logger.warning(f"Escaneo {scan_id} no existe")
                return None
                
            # Verificar si está terminado
            return self.dbmanager.scan_is_finished(scan_id)  # type: ignore
            
        except Exception as e:
            self.logger.error(
                f"Error al verificar si el escaneo {scan_id} está terminado: {e}"
            )
            return None


class NmapScanManager(_ScanManager):
    def __init__(self, user: User):
        super().__init__(user)
        self.dbmanager = NmapDBManager()
        self.logger.info("NmapScanManager inicializado correctamente")

    def _do_scan_and_save(
        self,
        scan_id: int,
        target_host: str,
        target_ports: str,
        timeout: int = 20,
    ) -> None:
        """
        Función ejecutada en thread separado.
        IMPORTANTE: Crea su propia sesión de BD para evitar conflictos.
        """
        thread_db = NmapDBManager()
        
        try:
            nmap_scan_model = thread_db.get_nmap_scan_by_id(scan_id)
            
            if not nmap_scan_model:
                self.logger.error(f"No se encontró escaneo Nmap con ID {scan_id}")
                return
            
            self.logger.info(
                f"Iniciando escaneo Nmap {scan_id}: target={target_host}, ports={target_ports}, timeout={timeout}"
            )

            task = NmapScanTask(target_host, target_ports, timeout=timeout)
            self.running_tasks[scan_id] = task

            self.logger.info(f"Ejecutando escaneo Nmap con ID {scan_id}")
            task.scan()
            task.wait()

            self.logger.info(
                f"Escaneo Nmap {scan_id} completado, procesando resultados"
            )
            results = JSONManager.convert_json_to_individual_nmap_data(
                task.results, nmap_scan_model #type: ignore
            )

            ports_count = len(results["ports"])
            self.logger.info(
                f"Procesando {ports_count} puertos del escaneo {scan_id}"
            )

            for port in results["ports"]:
                port_model = thread_db.get_or_create_port(port[0])
                thread_db.add_target_port(nmap_scan_model, port_model)
                thread_db.add_open_port(nmap_scan_model, port_model, port[2])

            nmap_scan_model.hostname = results["hostname"]
            nmap_scan_model.ended_at = datetime.now()
            
            thread_db.update_nmap_scan(nmap_scan_model)
            thread_db.set_scan_as_finished(nmap_scan_model)
           
            self.logger.info(
                f"Escaneo Nmap {scan_id} guardado exitosamente con {ports_count} puertos"
            )

        except Exception as e:
            self.logger.error(
                f"Error en escaneo Nmap {scan_id}: {str(e)}", exc_info=True
            )
            
            # Intentar actualizar el estado a error
            try:
                error_scan = thread_db.get_nmap_scan_by_id(scan_id)
                if error_scan:
                    error_scan.status = "error"
                    error_scan.ended_at = datetime.now()
                    thread_db.update_nmap_scan(error_scan)
            except Exception as update_err:
                self.logger.error(f"No se pudo actualizar estado de error: {update_err}")
        
        finally:
            try:
                thread_db.close_session()
                self.logger.debug(f"Sesión del thread para escaneo {scan_id} cerrada")
            except Exception as close_err:
                self.logger.warning(f"Error al cerrar sesión del thread: {close_err}")
            
            # Limpiar de running_tasks
            if scan_id in self.running_tasks:
                del self.running_tasks[scan_id]

    def run_task(self, target_host: str, target_ports: str, timeout: int = 20):
        try:
            if any(task.target == target_host for task in self.running_tasks.values() if hasattr(task, 'target')):
                self.logger.warning(
                    f"Intento de escaneo duplicado para target: {target_host}"
                )
                raise Exception(f"A scan is already running for target {target_host}")

            self.logger.info(f"Creando nuevo escaneo Nmap para {target_host}")
            
            nmap_scan_model = NmapScan(
                target=target_host, 
                user=self.active_user,
                started_at=datetime.now()
            )
            self.dbmanager.create_nmap_scan(nmap_scan_model)
            
            scan_id = nmap_scan_model.id

            self.logger.info(f"Escaneo Nmap {scan_id} creado, iniciando thread")
            self.thread = threading.Thread(
                target=self._do_scan_and_save,
                args=(scan_id, target_host, target_ports, timeout),
                daemon=True,
                name=f"NmapScan-{scan_id}"
            )
            self.thread.start()

            self.logger.info(
                f"Thread de escaneo Nmap {scan_id} iniciado exitosamente"
            )
            return scan_id

        except Exception as e:
            self.logger.error(f"Error al iniciar tarea Nmap: {str(e)}", exc_info=True)
            raise

    def get_scans_for_user(self) -> List:
        user_id = self.active_user.id
        
        try:
            self.logger.info(f"Obteniendo escaneos Nmap para usuario {user_id}")
            scans = self.dbmanager.get_nmap_scans_by_user(user_id)
            self.logger.info(f"Se obtuvieron {len(scans)} escaneos Nmap para usuario {user_id}")
            return scans
        except Exception as e:
            # Asegurar rollback antes de cualquier acceso adicional
            try:
                self.dbmanager.safe_rollback() #type: ignore
            except:
                pass
            
            self.logger.error(
                f"Error al obtener escaneos Nmap para usuario {user_id}: {str(e)}",
                exc_info=True,
            )
            raise

    def get_scan_by_id(self, id: int) -> Scan:
        try:
            self.logger.info(f"Obteniendo escaneo Nmap con ID: {id}")
            scan = self.dbmanager.get_scan_by_id(id)
            if scan:
                self.logger.info(f"Escaneo Nmap {id} obtenido exitosamente")
            else:
                self.logger.warning(f"Escaneo Nmap {id} no encontrado")
            return scan
        except Exception as e:
            self.logger.error(f"Error al obtener escaneo Nmap {id}: {str(e)}", exc_info=True)
            raise


class NiktoScanManager(_ScanManager):
    def __init__(self, user: User):
        super().__init__(user)
        self.dbmanager = NiktoDBManager()
        self.logger.info("NiktoScanManager inicializado correctamente")

    def _do_scan_and_save(
        self, 
        scan_id: int,  # CAMBIO: Recibe ID en lugar del objeto
        target_domain: str, 
        timeout: int = 60
    ) -> None:
        """
        Función ejecutada en thread separado.
        IMPORTANTE: Crea su propia sesión de BD para evitar conflictos.
        """
        # Crear DBManager exclusivo para este thread
        thread_db = NiktoDBManager()
        
        try:
            # Recuperar el escaneo con la sesión del thread
            nikto_scan_model = thread_db.get_nikto_scan_by_id(scan_id)
            
            if not nikto_scan_model:
                self.logger.error(f"No se encontró escaneo Nikto con ID {scan_id}")
                return
            
            self.logger.info(
                f"Iniciando escaneo Nikto {scan_id}: target={target_domain}, timeout={timeout}"
            )

            task = NiktoScanTask(target_domain, timeout)
            self.running_tasks[scan_id] = task

            self.logger.info(f"Ejecutando escaneo Nikto con ID {scan_id}")
            task.scan()
            task.wait()

            self.logger.info(
                f"Escaneo Nikto {scan_id} completado, procesando resultados"
            )
            results = JSONManager.convert_json_to_individual_nikto_data(task.results[-1]) # type: ignore
            task.results = results

            incidents_count = len(results)
            self.logger.info(
                f"Procesando {incidents_count} incidentes del escaneo Nikto {scan_id}"
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

                # Usar el DBManager del thread
                new_incident = thread_db.get_or_create_nikto_incident(incident)
                thread_db.add_incident(nikto_scan_model, new_incident)

            # Actualizar estado del escaneo
            nikto_scan_model.ended_at = datetime.now()
            thread_db.update_nikto_scan(nikto_scan_model)
            thread_db.set_scan_as_finished(nikto_scan_model)
            
            self.logger.info(
                f"Escaneo Nikto {scan_id} guardado exitosamente con {incidents_count} incidentes"
            )

        except Exception as e:
            self.logger.error(
                f"Error en escaneo Nikto {scan_id}: {str(e)}", exc_info=True
            )
            
            # Intentar actualizar el estado a error
            try:
                error_scan = thread_db.get_nikto_scan_by_id(scan_id)
                if error_scan:
                    error_scan.status = "error"
                    error_scan.ended_at = datetime.now()
                    thread_db.update_nikto_scan(error_scan)
            except Exception as update_err:
                self.logger.error(f"No se pudo actualizar estado de error: {update_err}")
        
        finally:
            # CRÍTICO: Cerrar la sesión del thread
            try:
                thread_db.close_session()
                self.logger.debug(f"Sesión del thread para escaneo {scan_id} cerrada")
            except Exception as close_err:
                self.logger.warning(f"Error al cerrar sesión del thread: {close_err}")
            
            # Limpiar de running_tasks
            if scan_id in self.running_tasks:
                del self.running_tasks[scan_id]

    def run_task(self, target_host: str, timeout: int = 60):
        try:

            self.logger.info(f"Creando nuevo escaneo Nikto para {target_host}")
            
            # Crear el escaneo con el dbmanager del thread principal
            nikto_scan_model = NiktoScan(
                target=target_host, 
                user=self.active_user,
                started_at=datetime.now()
            )
            self.dbmanager.create_nikto_scan(nikto_scan_model)
            
            # IMPORTANTE: Extraer el ID antes de lanzar el thread
            scan_id = nikto_scan_model.id

            self.logger.info(f"Escaneo Nikto {scan_id} creado, iniciando thread")
            
            # Lanzar thread pasando SOLO el ID, no el objeto completo
            self.thread = threading.Thread(
                target=self._do_scan_and_save, 
                args=(scan_id, target_host, timeout),
                daemon=True,
                name=f"NiktoScan-{scan_id}"
            )
            self.thread.start()

            self.logger.info(
                f"Thread de escaneo Nikto {scan_id} iniciado exitosamente"
            )
            return scan_id

        except Exception as e:
            self.logger.error(f"Error al iniciar tarea Nikto: {str(e)}", exc_info=True)
            raise

    def get_scans_for_user(self) -> List:
        # CRÍTICO: Guardar el ID antes de cualquier operación que pueda fallar
        user_id = self.active_user.id
        
        try:
            self.logger.info(f"Obteniendo escaneos Nikto para usuario {user_id}")
            scans = self.dbmanager.get_nikto_scans_by_user(user_id)
            self.logger.info(f"Se obtuvieron {len(scans)} escaneos Nikto para usuario {user_id}")
            return scans
        except Exception as e:
            # Asegurar rollback antes de cualquier acceso adicional
            try:
                self.dbmanager.safe_rollback() #type: ignore
            except:
                pass
                
            self.logger.error(
                f"Error al obtener escaneos Nikto para usuario {user_id}: {str(e)}",
                exc_info=True,
            )
            raise

    def get_scan_by_id(self, id: int) -> Scan:
        try:
            self.logger.info(f"Obteniendo escaneo Nikto con ID: {id}")
            scan = self.dbmanager.get_scan_by_id(id)
            if scan:
                self.logger.info(f"Escaneo Nikto {id} obtenido exitosamente")
            else:
                self.logger.warning(f"Escaneo Nikto {id} no encontrado")
            return scan
        except Exception as e:
            self.logger.error(
                f"Error al obtener escaneo Nikto {id}: {str(e)}", exc_info=True
            )
            raise