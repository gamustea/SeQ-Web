
from __future__ import annotations

# Standard library
import secrets
import threading
import time
from pathlib import Path
import urllib.parse
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Iterable


# Third party
import jwt

# SQLAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from pymysql.err import IntegrityError

# Local imports
from src.core.exceptions import ExistingUserError, UserBindingError, DatabaseError
from src.core.model import (
    AccessToken,
    FinishedScan,
    NiktoIncident,
    NiktoScan,
    NmapScan,
    OpenPort,
    Person,
    Port,
    RefreshToken,
    Scan,
    User,
)
from src.logic.secrets import Encoder
from src.logic.tasks import NmapScanTask, NiktoScanTask, TaskStatus, _Task
from src.misc.configread import ConfigReader
from src.misc.conversion import JSONManager
from src.misc.logging import SecOpsLogger





config_reader = ConfigReader()
(ACCESS_TOKEN_EXPIRE_MINUTES, 
 REFRESH_TOKEN_EXPIRE_DAYS, 
 JWT_SECRET_KEY, 
 JWT_ALGORITHM) = config_reader.get_oauth_config()


_ENGINE = None
_SESSION_FACTORY = None


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


def initialize_engine(database_url: Optional[str] = None): 
    """
    Inicializa el engine y el session factory una sola vez.
    Debe ser llamado al inicio de la aplicación.
    """
    global _ENGINE, _SESSION_FACTORY
    
    if _ENGINE is None:
        if database_url is None:
            # Obtener credenciales por defecto
            (USERNAME, PASSWORD, HOST, DBNAME) = ConfigReader().get_db_crendetials()
            database_url = (
                f"mysql+pymysql://{USERNAME}:{urllib.parse.quote(PASSWORD)}@{HOST}/{DBNAME}"
            )
        
        _ENGINE = create_engine(
            database_url,
            pool_pre_ping=True,
            pool_recycle=3600,
            echo=False,
            isolation_level="READ COMMITTED"
        )
        
        _SESSION_FACTORY = scoped_session(
            sessionmaker(
                bind=_ENGINE,
                expire_on_commit=False,
                autoflush=True,
                autocommit=False
            )
        )


class BaseManager:
    """
    Clase base para todos los managers que necesitan acceso a la BD.
    Proporciona gestión de sesiones thread-safe y métodos de utilidad.
    """
    
    def __init__(self, session: Optional[Session] = None):
        """
        Args:
            session: Sesión SQLAlchemy externa opcional. 
                     Si es None, usa la sesión del thread actual.
        """
        global _SESSION_FACTORY
        
        # Inicializar engine si no existe
        if _SESSION_FACTORY is None:
            initialize_engine()
        
        if session is not None:
            self.session = session
            self._owns_session = False
        else:
            self.session = _SESSION_FACTORY() # type: ignore
            self._owns_session = True
        
        self.logger = SecOpsLogger(self.__class__.__name__).get_logger()
    
    def _check_session(self):
        """Verifica que la sesión está activa"""
        if self.session is None:
            raise Exception("La sesión de base de datos no está establecida.")
    
    def close_session(self):
        """Cierra la sesión del thread actual si fue creada por este manager"""
        if self._owns_session and self.session is not None:
            try:
                self.session.close()
                _SESSION_FACTORY.remove() # type: ignore
            except Exception as e:
                self.logger.warning(f"Error al cerrar sesión: {e}")
    
    def _safe_commit(self):
        """Realiza un commit seguro con manejo de errores"""
        try:
            self.session.commit()
            return True
        except SQLAlchemyError as err:
            self.logger.error(f"Error durante commit: {err}")
            self._safe_rollback()
            raise
    
    def _safe_rollback(self):
        """Realiza un rollback seguro"""
        try:
            if self.session is not None:
                self.session.rollback()
                self.logger.debug("Rollback ejecutado exitosamente")
        except Exception as e:
            self.logger.warning(f"Error durante rollback: {e}")
            # Intentar recrear sesión si falla
            try:
                if self._owns_session:
                    self.session.close()
                    global _SESSION_FACTORY
                    if _SESSION_FACTORY is not None:
                        self.session = _SESSION_FACTORY()
                        self.logger.info("Sesión recreada después de error en rollback")
            except Exception as recreate_err:
                self.logger.error(f"No se pudo recrear la sesión: {recreate_err}")
    
    @staticmethod
    def close_all_sessions():
        """Cierra todas las sesiones y limpia el factory"""
        global _SESSION_FACTORY
        if _SESSION_FACTORY is not None:
            _SESSION_FACTORY.remove()


class ScanManager(BaseManager, ABC):
    """
    Clase base para gestores de escaneos.
    Define la interfaz común para todos los gestores de escaneos.
    """
    active_user: User
    running_tasks: dict[int, _Task] = {}

    def __init__(self, user: User, session: Optional[Session] = None):
        super().__init__(session)
        self.active_user = user      
        
    def get_scan_progress(self, scan_id: int) -> Optional[int]:
        """Obtiene el progreso de un escaneo en ejecución"""
        if scan_id in self.running_tasks:
            progress = self.running_tasks[scan_id].progress
            self.logger.debug(f"Progreso de escaneo {scan_id}: {progress}%")
            return progress
        
        self.logger.warning(f"Escaneo {scan_id} no está en ejecución")
        return None
    
    def get_scans_for_user(self) -> List[Scan]:
        """Obtiene todos los escaneos del usuario activo"""
        user_id = self.active_user.id
        try:
            self._check_session()
            self.logger.info(f"Obteniendo escaneos Nikto para usuario {user_id}")
            
            scans = self.session.query(Scan).filter(
                Scan.user_id == user_id
            ).all()
            
            self.logger.info(f"Se obtuvieron {len(scans)} escaneos Nikto")
            return scans
        
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error obteniendo escaneos: {str(e)}", exc_info=True)
            raise
    
    def get_scan_by_id(self, scan_id: int) -> Optional[Scan]:
        """Obtiene un escaneo específico por ID"""
        try:
            self._check_session()
            self.logger.info(f"Obteniendo escaneo Nikto {scan_id}")
            
            scan = self.session.query(Scan).filter(
                Scan.id == scan_id
            ).one_or_none()
            
            if scan:
                self.logger.info(f"Escaneo de Nikto {scan_id} encontrado")
            else:
                self.logger.warning(f"Escaneo de Nikto {scan_id} no encontrado")
            
            return scan
        
        except Exception as e:
            self.logger.error(f"Error obteniendo escaneo {scan_id}: {e}", exc_info=True)
            raise
    
    def delete_scan(self, scan_id: int) -> bool:
        """Elimina un escaneo y sus relaciones"""
        try:
            self._check_session()
            scan = self.get_scan_by_id(scan_id)
            
            if not scan:
                self.logger.warning(f"Escaneo {scan_id} no existe")
                return False
            
            self.session.delete(scan)
            self._safe_commit()
            
            self.logger.info(f"Escaneo {scan_id} eliminado")
            return True
        
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error eliminando escaneo {scan_id}: {e}")
            raise

    def is_scan_finished(self, scan_id: int) -> Optional[bool]:
        """Verifica si un escaneo ha finalizado"""
        try:
            self._check_session()

            if not self._scan_exists(scan_id):
                self.logger.warning(f"Escaneo {scan_id} no existe")
                return None
        
            # Verificar si está marcado como finalizado
            self.session.commit()  # Cerrar transacción actual
            
            result = self.session.execute(
                text("SELECT COUNT(*) FROM FinishedScan WHERE id = :scan_id"),
                {"scan_id": scan_id}
            )
            
            count = result.scalar()
            is_finished = count > 0 # type: ignore
            
            self.logger.debug(f"Escaneo {scan_id} finalizado: {is_finished}")
            return is_finished
        
        except Exception as e:
            self.logger.error(f"Error verificando estado de escaneo {scan_id}: {e}")
            self._safe_rollback()
            return None

    def _scan_exists(self, scan_id: int) -> bool:
        """Verifica si existe un escaneo"""
        self._check_session()
        numero_de_filas = self.session.query(Scan).filter(
            Scan.id == scan_id
        ).count()
        return numero_de_filas > 0

    def get_scan_task_status(self, scan_id: int) -> Optional[str]:
        """Obtiene el estado de un escaneo en ejecución"""
        if scan_id in self.running_tasks:
            status = self.running_tasks[scan_id].status
            self.logger.debug(f"Estado de escaneo {scan_id}: {status}")
            return str(status)
        
        if self.is_scan_finished(scan_id):
            self.logger.debug(f"Escaneo {scan_id} está COMPLETADO")
            return str(TaskStatus.COMPLETED)
        
        self.logger.warning(f"Escaneo {scan_id} no está en ejecución")
        return None


class NmapScanManager(ScanManager):
    """
    Gestor completo para escaneos Nmap.
    Maneja tanto la ejecución de tareas como la persistencia.
    """
    
    def __init__(self, user: User, session=None):
        super().__init__(user, session)
        self.logger.info(f"NmapScanManager inicializado para usuario: {user.id}")

    # =================================================================
    # MÉTODOS DE GESTIÓN DE TAREAS (lógica de negocio)
    # =================================================================

    def run_scan(self, target_host: str, target_ports: str, timeout: int = 20) -> int:
        """
        Inicia un nuevo escaneo Nmap de forma asíncrona.
        
        Returns:
            int: ID del escaneo creado
        """
        try:
            # Validar que no haya escaneo duplicado
            if any(task.target == target_host for task in self.running_tasks.values() 
                if hasattr(task, 'target')):
                    raise Exception(f"A scan is already running for target {target_host}")
            
            self.logger.info(f"Creando nuevo escaneo Nmap para {target_host}")
            
            # Crear registro en BD
            nmap_scan = NmapScan(
                target=target_host,
                user=self.active_user,
                started_at=datetime.now()
            )
            
            self.session.add(nmap_scan)
            self._safe_commit()
            
            scan_id = nmap_scan.id
            self.logger.info(f"Escaneo Nmap {scan_id} creado, iniciando thread")
            
            # ✅ CORRECCIÓN: daemon=False para que complete su trabajo
            thread = threading.Thread(
                target=self._execute_scan_thread,
                args=(scan_id, target_host, target_ports, timeout),
                daemon=False,  # ✅ CRÍTICO: No daemon
                name=f"NmapScan-{scan_id}"
            )
            thread.start()
            
            # ✅ Pequeña pausa para que el thread arranque
            time.sleep(0.2)
            
            self.logger.info(f"Thread de escaneo Nmap {scan_id} iniciado")
            return scan_id # type: ignore
        
        except Exception as e:
            self.logger.error(f"Error al iniciar escaneo Nmap: {str(e)}", exc_info=True)
            raise

    # =================================================================
    # MÉTODOS PRIVADOS (implementación interna)
    # =================================================================
    
    def _execute_scan_thread(
        self, 
        scan_id: int, 
        target_host: str, 
        target_ports: str, 
        timeout: int
    ) -> None:
        """
        Ejecuta el escaneo en un thread separado con su propia sesión de BD.
        """
        # Crear manager exclusivo para este thread
        thread_manager = NmapScanManager(self.active_user)
        
        try:
            # Recuperar el escaneo
            scan = thread_manager.get_scan_by_id(scan_id)
            if not scan:
                thread_manager.logger.error(f"No se encontró escaneo {scan_id}")
                return
            
            thread_manager.logger.info(f"Iniciando escaneo Nmap {scan_id}")
            
            # Ejecutar tarea de escaneo
            task = NmapScanTask(target_host, target_ports, timeout=timeout)
            self.running_tasks[scan_id] = task
            
            # ✅ CORRECCIÓN: scan() es NO bloqueante ahora
            task.scan()
            
            # ✅ CORRECCIÓN: wait() con timeout apropiado
            # Debe ser mayor que el timeout del comando para dar margen
            wait_timeout = timeout + 30
            success = task.wait(timeout=wait_timeout)
            
            if not success:
                thread_manager.logger.error(
                    f"Escaneo {scan_id} falló o excedió timeout. Estado: {task.status}"
                )
                # Marcar como error en BD
                scan.ended_at = datetime.now()
                thread_manager.session.add(scan)
                thread_manager._safe_commit()
                return
            
            # ✅ CORRECCIÓN: Verificar que results no sea None
            if task.results is None:
                thread_manager.logger.error(
                    f"Escaneo {scan_id} completó pero no tiene resultados"
                )
                scan.ended_at = datetime.now()
                thread_manager.session.add(scan)
                thread_manager._safe_commit()
                return
            
            thread_manager.logger.info(
                f"Escaneo {scan_id} completado, guardando resultados"
            )
            
            # Procesar y guardar resultados
            thread_manager._save_scan_results(scan, task.results)
            thread_manager.logger.info(f"Escaneo {scan_id} guardado exitosamente")
        
        except Exception as e:
            thread_manager.logger.error(
                f"Error en escaneo {scan_id}: {e}", 
                exc_info=True
            )
            
            # Marcar como error
            try:
                error_scan = thread_manager.get_scan_by_id(scan_id)
                if error_scan:
                    error_scan.ended_at = datetime.now()
                    thread_manager.session.add(error_scan)
                    thread_manager._safe_commit()
            except Exception as update_err:
                thread_manager.logger.error(
                    f"No se pudo actualizar estado de error: {update_err}"
                )
        
        finally:
            # Limpiar
            thread_manager.close_session()
            if scan_id in self.running_tasks:
                del self.running_tasks[scan_id]
    
    def _save_scan_results(self, scan: NmapScan, results: dict) -> None:
        """Procesa y guarda los resultados del escaneo"""
        try:
            # Convertir resultados JSON
            processed_results = JSONManager.convert_json_to_individual_nmap_data(
                results, scan # type: ignore
            )
            
            ports_count = len(processed_results["ports"])
            self.logger.info(f"Procesando {ports_count} puertos del escaneo {scan.id}")
            
            # Guardar puertos
            for port_data in processed_results["ports"]:
                port_protocol, _, port_reason = port_data
                
                # Get or create port
                port = self._get_or_create_port(port_protocol)
                
                # Agregar a target_ports
                if port not in scan.target_ports:
                    scan.target_ports.append(port)
                
                # Crear OpenPort
                open_port = OpenPort(
                    nmap_scan_id=scan.id,
                    port_id=port.id,
                    reason=port_reason
                )
                self.session.add(open_port)
            
            # Actualizar scan
            scan.hostname = processed_results["hostname"]
            scan.ended_at = datetime.now()
            self.session.add(scan)
            
            # Marcar como finalizado
            finished_scan = FinishedScan(id=scan.id)
            finished_scan.finished_at = datetime.now() # type: ignore
            self.session.add(finished_scan)
            
            self.session.flush()
            self._safe_commit()
            
            self.logger.info(f"Escaneo {scan.id} guardado con {ports_count} puertos")
        
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error guardando resultados: {e}", exc_info=True)
            raise
    
    def _get_or_create_port(self, protocol: str) -> Port:
        """Obtiene un puerto existente o crea uno nuevo"""
        self._check_session()
        
        port = self.session.query(Port).filter(Port.protocol == protocol).one_or_none()
        
        if port:
            self.logger.debug(f"Puerto '{protocol}' ya existe")
            return port
        
        # Crear nuevo
        new_port = Port(protocol=protocol)
        self.session.add(new_port)
        self.session.flush()
        
        self.logger.info(f"Puerto '{protocol}' creado con ID {new_port.id}")
        return new_port


class NiktoScanManager(ScanManager):
    """
    Gestor completo para escaneos Nikto.
    Maneja tanto la ejecución de tareas como la persistencia.
    """
    
    def __init__(self, user: User, session=None):
        super().__init__(user, session)
        self.logger.info(f"NiktoScanManager inicializado para usuario: {user.id}")
    
    # =================================================================
    # MÉTODOS DE GESTIÓN DE TAREAS (lógica de negocio)
    # =================================================================
    
    def run_scan(self, target_domain: str, timeout: int = 60) -> int:
        """
        Inicia un nuevo escaneo Nikto de forma asíncrona.
        """
        try:
            self.logger.info(f"Creando nuevo escaneo Nikto para {target_domain}")
            
            # Crear registro en BD
            nikto_scan = NiktoScan(
                target=target_domain,
                user=self.active_user,
                started_at=datetime.now()
            )
            
            self.session.add(nikto_scan)
            self._safe_commit()
            
            scan_id = nikto_scan.id
            self.logger.info(f"Escaneo Nikto {scan_id} creado, iniciando thread")
            
            # ✅ CORRECCIÓN: daemon=False
            thread = threading.Thread(
                target=self._execute_scan_thread,
                args=(scan_id, target_domain, timeout),
                daemon=False,  # ✅ CRÍTICO
                name=f"NiktoScan-{scan_id}"
            )
            thread.start()
            
            # ✅ Pequeña pausa
            time.sleep(0.2)
            
            self.logger.info(f"Thread de escaneo Nikto {scan_id} iniciado")
            return scan_id # type: ignore
        
        except Exception as e:
            self.logger.error(f"Error al iniciar escaneo Nikto: {str(e)}", exc_info=True)
            raise

    
    # =================================================================
    # MÉTODOS PRIVADOS (implementación interna)
    # =================================================================
    
    def _execute_scan_thread(
        self, 
        scan_id: int, 
        target_domain: str, 
        timeout: int
    ) -> None:
        """
        Ejecuta el escaneo en un thread separado.
        """
        thread_manager = NiktoScanManager(self.active_user)
        
        try:
            scan = thread_manager.get_scan_by_id(scan_id)
            if not scan:
                thread_manager.logger.error(f"No se encontró escaneo {scan_id}")
                return
            
            thread_manager.logger.info(f"Iniciando escaneo Nikto {scan_id}")
            
            # Ejecutar tarea
            task = NiktoScanTask(target_domain, timeout=timeout)
            self.running_tasks[scan_id] = task
            
            # ✅ scan() no bloqueante
            task.scan()
            
            # ✅ wait() con timeout apropiado
            wait_timeout = timeout + 30
            success = task.wait(timeout=wait_timeout)
            
            if not success or task.results is None:
                thread_manager.logger.error(
                    f"Escaneo {scan_id} falló o no tiene resultados. Estado: {task.status}"
                )
                scan.ended_at = datetime.now()
                thread_manager.session.add(scan)
                thread_manager._safe_commit()
                return
            
            thread_manager.logger.info(
                f"Escaneo {scan_id} completado, guardando resultados"
            )
            
            # Procesar y guardar resultados
            thread_manager._save_scan_results(scan, task.results)
            thread_manager.logger.info(f"Escaneo {scan_id} guardado exitosamente")
        
        except Exception as e:
            thread_manager.logger.error(f"Error en escaneo {scan_id}: {e}", exc_info=True)
            
            try:
                error_scan = thread_manager.get_scan_by_id(scan_id)
                if error_scan:
                    error_scan.ended_at = datetime.now()
                    thread_manager.session.add(error_scan)
                    thread_manager._safe_commit()
            except Exception as update_err:
                thread_manager.logger.error(
                    f"No se pudo actualizar estado de error: {update_err}"
                )
        
        finally:
            thread_manager.close_session()
            if scan_id in self.running_tasks:
                del self.running_tasks[scan_id]
    
    def _save_scan_results(self, scan: NiktoScan, results: list) -> None:
        """Procesa y guarda los resultados del escaneo Nikto"""
        try:
            # Convertir resultados JSON
            processed_results = JSONManager.convert_json_to_individual_nikto_data(
                results[-1] if results else {}
            )
            
            incidents_count = len(processed_results)
            self.logger.info(f"Procesando {incidents_count} incidentes del escaneo {scan.id}")
            
            # Guardar incidentes
            for incident_data in processed_results:
                description = incident_data["description"]
                osvdbid = incident_data["osvdbid"]
                method = incident_data["method"]
                uri = incident_data["uri"]
                
                # Crear incidente
                incident = NiktoIncident()
                incident.description = description
                incident.osvdb_id = osvdbid
                incident.method = method
                incident.url = uri
                
                # Asignar severidad
                self._assign_severity_to_incident(incident)
                
                # Get or create incident
                db_incident = self._get_or_create_incident(incident)
                
                # Asociar al scan
                if db_incident not in scan.incidents:
                    scan.incidents.append(db_incident)
            
            # Actualizar scan
            scan.ended_at = datetime.now()
            self.session.add(scan)
            
            # Marcar como finalizado
            finished_scan = FinishedScan(id=scan.id)
            finished_scan.finished_at = datetime.now() # type: ignore
            self.session.add(finished_scan)
            
            self.session.flush()
            self._safe_commit()
            
            self.logger.info(f"Escaneo {scan.id} guardado con {incidents_count} incidentes")
        
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error guardando resultados: {e}", exc_info=True)
            raise
    
    def _get_or_create_incident(self, incident: NiktoIncident) -> NiktoIncident:
        """Obtiene un incidente existente o crea uno nuevo"""
        self._check_session()
        
        # Buscar por descripción y OSVDB ID
        existing = self.session.query(NiktoIncident).filter(
            NiktoIncident.description == incident.description,
            NiktoIncident.osvdb_id == incident.osvdb_id
        ).first()
        
        if existing:
            self.logger.debug(f"Incidente ya existe: {incident.osvdb_id}")
            return existing
        
        # Crear nuevo
        self.session.add(incident)
        self.session.flush()
        
        self.logger.info(f"Incidente creado: {incident.osvdb_id}")
        return incident
    
    def _assign_severity_to_incident(self, incident: NiktoIncident) -> None:
        """
        Asigna la severidad a un incidente de Nikto basándose en patrones.
        """
        desc = incident.description.lower() if incident.description else "" # type: ignore
        url = incident.url.lower() if incident.url else "" # type: ignore
        method = incident.method.upper() if incident.method else "" # type: ignore
        
        # CRITICAL - Exposición de archivos sensibles
        critical_patterns = [
            ".env", "env.production", "env.local", ".git/", ".git/config",
            "phpinfo", "config.php", "database.yml", "wp-config.php",
            "web.config", ".sql", "backup.sql", "passwd", "shadow",
            "credentials", "private_key", "id_rsa", "config.bak",
            "shell", "webshell", "backdoor", "remote code execution",
            "command injection", "sql injection", "unrestricted file upload"
        ]
        
        for pattern in critical_patterns:
            if pattern in desc or pattern in url:
                incident.severity = "CRITICAL" # type: ignore
                return
        
        # HIGH - Vulnerabilidades explotables
        high_patterns = [
            "outdated", "vulnerable version", "known vulnerability", "cve-",
            "xss", "cross site scripting", "csrf", "authentication bypass",
            "authorization bypass", "privilege escalation", "directory traversal",
            "path traversal", "../", "local file inclusion", "remote file inclusion",
            "weak ssl", "weak tls", "ssl v2", "ssl v3", "poodle", "heartbleed",
            "shellshock", "default password", "default credential", "weak cipher"
        ]
        
        dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]
        
        for pattern in high_patterns:
            if pattern in desc or pattern in url:
                incident.severity = "HIGH" # type: ignore
                return
        
        if method in dangerous_methods and "allowed" in desc:
            incident.severity = "HIGH" # type: ignore
            return
        
        # MEDIUM - Problemas de configuración
        medium_patterns = [
            "directory indexing", "directory listing", "missing security header",
            "x-frame-options", "x-content-type-options", "content-security-policy",
            "strict-transport-security", "clickjacking", "information disclosure",
            "stack trace", "error message", "debug mode", "source code disclosure",
            "session fixation", "cookie without", "cookie httponly", "cookie secure",
            "unencrypted", "http basic auth", "robots.txt", "sitemap.xml",
            "cors misconfiguration", "open redirect", "server-status", "admin panel"
        ]
        
        for pattern in medium_patterns:
            if pattern in desc or pattern in url:
                incident.severity = "MEDIUM" # type: ignore
                return
        
        # LOW - Problemas menores
        low_patterns = [
            "server banner", "server header", "x-powered-by", "server version",
            "apache/", "nginx/", "microsoft-iis", "options method", "head method",
            "default page", "default installation", "test page", "uncommon header",
            "missing header", "cache control", "ip address", "internal ip"
        ]
        
        for pattern in low_patterns:
            if pattern in desc or pattern in url:
                incident.severity = "LOW" # type: ignore
                return
        
        # INFO - Hallazgos informativos
        info_patterns = [
            "the site uses", "appears to be", "may be", "possibly",
            "cookie created", "retrieved", "hostname resolves", "scan completed"
        ]
        
        for pattern in info_patterns:
            if pattern in desc:
                incident.severity = "INFO" # type: ignore
                return
        
        # Default
        incident.severity = "MEDIUM" # type: ignore


class UserManager(BaseManager):
    """
    Gestor completo para usuarios y personas.
    Integra funcionalidad de UserDBManager y UserUtilities.
    """
    
    # ========================================================================
    # MÉTODOS DE AUTENTICACIÓN Y VALIDACIÓN
    # ========================================================================
    
    def verify_credentials(self, username: str, password: str) -> Tuple[bool, Optional[int]]:
        """
        Verifica las credenciales de un usuario.
        
        Args:
            username: Nombre de usuario
            password: Contraseña en texto plano
        
        Returns:
            Tupla (es_válido, user_id)
            - (True, user_id) si las credenciales son válidas
            - (False, None) si son inválidas
        """
        self._check_session()
        try:
            user = self.session.query(User).filter(
                User.username == username
            ).one_or_none()
            
            if not user:
                self.logger.info(f"Usuario '{username}' no encontrado")
                return False, None
            
            # Verificar contraseña con salt
            valid_password = Encoder.verify_password(
                stored_hash=user.password_hash, # type: ignore
                password=password,
                salt=user.password_salt # type: ignore
            )
            
            if not valid_password:
                self.logger.warning(f"Contraseña incorrecta para usuario '{username}'")
                return False, None
            
            user_id = user.id
            
            # Desasociar el objeto de la sesión para evitar conflictos
            self.session.expunge(user)
            
            self.logger.info(f"Credenciales válidas para usuario '{username}' (ID: {user_id})")
            return True, user_id # type: ignore
        
        except SQLAlchemyError as err:
            self.logger.error(f"Error al validar credenciales: {err}")
            raise
    
    def validate_credentials_simple(self, username: str, password: str) -> bool:
        """
        Valida credenciales sin devolver el user_id (para compatibilidad).
        
        Args:
            username: Nombre de usuario
            password: Contraseña en texto plano
        
        Returns:
            True si las credenciales son válidas, False si no
        """
        is_valid, _ = self.verify_credentials(username, password)
        return is_valid
    
    # ========================================================================
    # MÉTODOS DE GESTIÓN DE USUARIOS
    # ========================================================================
    
    def user_exists(self, username: str) -> bool:
        """Verifica si existe un usuario"""
        self._check_session()
        try:
            exists = self.session.query(User).filter(
                User.username == username
            ).count() > 0
            
            self.logger.info(f"Usuario '{username}' existe: {exists}")
            return exists
        
        except SQLAlchemyError as err:
            self.logger.error(f"Error verificando existencia de usuario: {err}")
            raise
    
    def create_user(self, user: User) -> None:
        """
        Crea un nuevo usuario (y su persona si no existe).
        
        Args:
            user: Objeto User a crear
        
        Raises:
            ExistingUserError: Si el usuario ya existe
        """
        self._check_session()
        try:
            # Verificar si ya existe
            if self.user_exists(user.username): # type: ignore
                raise ExistingUserError(username=user.username) # type: ignore
            
            # Verificar/crear persona si es necesario
            if user.person_id: # type: ignore
                if not self._person_exists(user.person_id): # type: ignore
                    if user.person:
                        self._create_person(user.person)
            elif user.person:
                self._create_person(user.person)
            
            self.session.add(user)
            self._safe_commit()
            
            self.logger.info(f"Usuario '{user.username}' creado con ID {user.id}")
        
        except ExistingUserError:
            raise
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error creando usuario: {err}")
            raise
    
    def sign_in_user(self, username: str, password: str, email: str, alias: str) -> User:
        """
        Registra un nuevo usuario vinculándolo a una persona existente.
        
        Args:
            username: Nombre de usuario
            password: Contraseña en texto plano
            email: Email de la persona existente
        
        Returns:
            Usuario creado
        
        Raises:
            ExistingUserError: Si el usuario ya existe
            UserBindingError: Si no existe una persona con ese email
        """
        self._check_session()
        try:

            if self.user_exists(username):
                raise ExistingUserError(username)

            person = self.get_person_by_alias(alias)

            if not person:
                raise UserBindingError(
                    username=username, 
                    alias=alias
                )           
            
            # Generar hash de contraseña con salt
            salt = Encoder.generate_salt()
            hashed_password = Encoder.hash_password_with_salt(password, salt)
            
            # Crear usuario
            new_user = User(
                username=username,
                password_hash=hashed_password,
                password_salt=salt,
                email=email,
                person_id=person.id
            )
            
            self.session.add(new_user)
            self._safe_commit()

            # Desasociar para evitar conflictos
            self.session.expunge(new_user)
            
            self.logger.info(f"Usuario '{username}' registrado exitosamente")
            return new_user
        
        except (ExistingUserError, UserBindingError):
            self._safe_rollback()
            raise
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error registrando usuario: {err}")
            raise DatabaseError("Hubo un problema con tus credenciales. Revísalas, y vuelve a intentarlo.")
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Obtiene un usuario por su username"""
        self._check_session()
        try:
            user = self.session.query(User).filter(
                User.username == username
            ).one_or_none()
            
            if user:
                self.logger.info(f"Usuario '{username}' obtenido")
            else:
                self.logger.info(f"Usuario '{username}' no encontrado")
            
            return user
        
        except SQLAlchemyError as err:
            self.logger.error(f"Error obteniendo usuario: {err}")
            raise
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Obtiene un usuario por ID"""
        self._check_session()
        try:
            user = self.session.query(User).filter(User.id == user_id).one_or_none()
            
            if user:
                self.logger.debug(f"Usuario con ID {user_id} obtenido")
            else:
                self.logger.warning(f"Usuario con ID {user_id} no encontrado")
            
            return user
        
        except SQLAlchemyError as err:
            self.logger.error(f"Error obteniendo usuario por ID: {err}")
            raise
    
    def get_all_users(self) -> list[User]:
        """Obtiene todos los usuarios"""
        self._check_session()
        try:
            users = self.session.query(User).all()
            self.logger.info(f"Se obtuvieron {len(users)} usuarios")
            return users
        
        except SQLAlchemyError as err:
            self.logger.error(f"Error obteniendo todos los usuarios: {err}")
            raise
    
    def update_user_password(self, user: User, new_password: str) -> None:
        """
        Actualiza la contraseña de un usuario (generando nuevo salt).
        
        Args:
            user: Usuario a actualizar
            new_password: Nueva contraseña en texto plano
        """
        self._check_session()
        try:
            # Generar nuevo salt y hash
            new_salt = Encoder.generate_salt()
            new_hashed_password = Encoder.hash_password_with_salt(new_password, new_salt)
            
            user.password_salt = new_salt # type: ignore
            user.password_hash = new_hashed_password # type: ignore
            
            self.session.add(user)
            self._safe_commit()
            
            self.logger.info(f"Contraseña actualizada para usuario {user.id}")
        
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error actualizando contraseña: {err}")
            raise
    
    def update_user_password_by_id(self, user_id: int, new_password: str) -> None:
        """
        Actualiza la contraseña de un usuario por ID.
        
        Args:
            user_id: ID del usuario
            new_password: Nueva contraseña en texto plano
        
        Raises:
            UserBindingError: Si no existe el usuario
        """
        user = self.get_user_by_id(user_id)
        
        if not user:
            raise UserBindingError(
                username=str(user_id), 
                alias="unknown"
            )
        
        self.update_user_password(user, new_password)
    
    def delete_user(self, user: User) -> None:
        """Elimina un usuario"""
        self._check_session()
        try:
            self.session.delete(user)
            self._safe_commit()
            
            self.logger.info(f"Usuario {user.id} eliminado")
        
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error eliminando usuario: {err}")
            raise
    
    # ========================================================================
    # MÉTODOS DE GESTIÓN DE PERSONAS
    # ========================================================================
    
    def sign_in_person(self, first_name: str, last_name: str, alias: str) -> Person:
        """
        Registra una nueva persona.
        
        Args:
            first_name: Nombre
            last_name: Apellido      
        Returns:
            Persona creada
        
        Raises:
            ExistingUserError: Si ya existe una persona con ese email
        """
        self._check_session()
        try:

            person = self.get_person_by_alias(alias)

            if person:
                raise ExistingUserError(f"El usuario {alias} ya está en la base de datos")
           
            # Crear persona
            person = Person(
                first_name=first_name,
                last_name=last_name,
                alias=alias
            )
            
            self._create_person(person)
            
            self.logger.info(f"Persona registrada: {first_name} {last_name}")
            return person
        
        except ExistingUserError:
            raise
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error registrando persona: {err}")
            raise

    def get_person_by_alias(self, alias: str) -> Optional[Person]:
        """Obtiene una persona por su email"""
        self._check_session()
        try:
            person = self.session.query(Person).filter(
                Person.alias == alias
            ).one_or_none()
            
            if person:
                self.logger.info(f"Persona con email '{alias}' obtenida")
            else:
                self.logger.info(f"Persona con email '{alias}' no encontrada")
            
            return person
        
        except SQLAlchemyError as err:
            self.logger.error(f"Error obteniendo persona por email: {err}")
            raise

    def get_person_by_email(self, email: str) -> Optional[Person]:
        
        """Obtiene una persona por su email"""
        self._check_session()
        try:
            person = self.session.query(Person).filter(
                Person.email == email
            ).one_or_none()
            
            if person:
                self.logger.info(f"Persona con email '{email}' obtenida")
            else:
                self.logger.info(f"Persona con email '{email}' no encontrada")
            
            return person
        
        except SQLAlchemyError as err:
            self.logger.error(f"Error obteniendo persona por email: {err}")
            raise
    
    def get_person_by_id(self, person_id: int) -> Optional[Person]:
        """Obtiene una persona por ID"""
        self._check_session()
        try:
            person = self.session.query(Person).filter(
                Person.id == person_id
            ).one_or_none()
            
            if person:
                self.logger.debug(f"Persona con ID {person_id} obtenida")
            
            return person
        
        except SQLAlchemyError as err:
            self.logger.error(f"Error obteniendo persona por ID: {err}")
            raise
    
    def get_all_people(self) -> list[Person]:
        """Obtiene todas las personas"""
        self._check_session()
        try:
            people = self.session.query(Person).all()
            self.logger.info(f"Se obtuvieron {len(people)} personas")
            return people
        
        except SQLAlchemyError as err:
            self.logger.error(f"Error obteniendo todas las personas: {err}")
            raise
    
    def update_person(self, person: Person) -> None:
        """Actualiza la información de una persona"""
        self._check_session()
        try:
            existing_person = self.session.query(Person).filter(
                Person.id == person.id
            ).one_or_none()
            
            if existing_person:
                existing_person.first_name = person.first_name
                existing_person.last_name = person.last_name
                existing_person.email = person.email
                
                self._safe_commit()
                self.logger.info(f"Persona con ID {person.id} actualizada")
            else:
                self.logger.warning(f"Persona con ID {person.id} no encontrada")
        
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error actualizando persona: {err}")
            raise
    
    def delete_person(self, person: Person) -> None:
        """Elimina una persona"""
        self._check_session()
        try:
            self.session.delete(person)
            self._safe_commit()
            
            self.logger.info(f"Persona con ID {person.id} eliminada")
        
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error eliminando persona: {err}")
            raise
    
    # ========================================================================
    # MÉTODOS PRIVADOS
    # ========================================================================
    
    def _person_exists(self, person_id: int) -> bool:
        """Verifica si existe una persona por ID"""
        self._check_session()
        return self.session.query(Person).filter(
            Person.id == person_id
        ).count() > 0
    
    def _create_person(self, person: Person) -> None:
        """Crea una nueva persona (método interno)"""
        self._check_session()
        try:
            self.session.add(person)
            self.session.flush()
            self.logger.info(f"Persona creada: {person.first_name} {person.last_name} (ID: {person.id})")
        
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error creando persona: {err}")
            raise


class OAuthTokenManager(BaseManager):
    """Gestor de tokens OAuth 2.0 usando JWT"""
    
    def create_access_token(self, user_id: int, username: str) -> str:
        """Crea un JWT access token"""
        expires_at = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        payload = {
            "sub": str(user_id),  # subject (user ID)
            "username": username,
            "exp": expires_at,  # expiration time
            "iat": datetime.utcnow(),  # issued at
            "type": "access"
        }
        
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        # Guardar en DB
        access_token_record = AccessToken(
            token=token,
            user_id=user_id,
            expires_at=expires_at
        )
        self.session.add(access_token_record)
        self._safe_commit()
        
        return token
    
    def create_refresh_token(self, user_id: int) -> str:
        """Crea un refresh token opaco (no JWT)"""
        token = secrets.token_urlsafe(64)
        expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        
        refresh_token_record = RefreshToken(
            token=token,
            user_id=user_id,
            expires_at=expires_at
        )
        self.session.add(refresh_token_record)
        self._safe_commit()
        
        return token
    
    def verify_access_token(self, token: str) -> Optional[dict]:
        """
        Verifica y decodifica un access token.
        Returns: Payload del token si es válido, None si no lo es
        """
        try:
            # Decodificar JWT
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
            # Verificar tipo
            if payload.get("type") != "access":
                return None
            
            # Verificar si está revocado en DB
            token_record = self.session.query(AccessToken).filter(
                AccessToken.token == token
            ).one_or_none()
            
            if not token_record or not token_record.is_valid():
                return None
            
            return payload
        
        except jwt.ExpiredSignatureError:
            return None  # Token expirado
        except jwt.InvalidTokenError:
            return None  # Token inválido
        except Exception as e:
            return None
    
    def verify_refresh_token(self, token: str) -> Optional[int]:
        """
        Verifica un refresh token.
        Returns: user_id si es válido, None si no lo es
        """
        try:
            token_record = self.session.query(RefreshToken).filter(
                RefreshToken.token == token
            ).one_or_none()
            
            if not token_record or not token_record.is_valid():
                return None
            
            return token_record.user_id # type: ignore
        
        except Exception:
            return None
    
    def revoke_access_token(self, token: str) -> bool:
        """Revoca un access token"""
        try:
            token_record = self.session.query(AccessToken).filter(
                AccessToken.token == token
            ).one_or_none()
            
            if token_record:
                token_record.revoked = 1 # type: ignore
                self._safe_commit()
                return True
            return False
        except Exception:
            return False
    
    def revoke_all_user_tokens(self, user_id: int) -> None:
        """Revoca todos los tokens de un usuario"""
        try:
            self.session.query(AccessToken).filter(
                AccessToken.user_id == user_id
            ).update({"revoked": 1})
            
            self.session.query(RefreshToken).filter(
                RefreshToken.user_id == user_id
            ).update({"revoked": 1})
            
            self._safe_commit()
        except Exception as e:
            self._safe_rollback()
            raise
    
    def cleanup_expired_tokens(self) -> None:
        """Elimina tokens expirados de la DB (ejecutar periódicamente)"""
        try:
            now = datetime.utcnow()
            
            self.session.query(AccessToken).filter(
                AccessToken.expires_at < now
            ).delete()
            
            self.session.query(RefreshToken).filter(
                RefreshToken.expires_at < now
            ).delete()
            
            self._safe_commit()
        except Exception:
            self._safe_rollback()