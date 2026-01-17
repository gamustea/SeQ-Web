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

from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional, Dict
import time


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
    Host,
    OpenVASScan,
    OpenVASVulnerability,
    OpenVASScanResult
)
from src.logic.secrets import Encoder
from src.logic.tasks import NmapScanTask, NiktoScanTask, TaskStatus, _Task
from src.misc.configread import ConfigReader
from src.misc.conversion import JSONManager
from src.misc.logging import SecOpsLogger
from src.misc.inetutils import normalize_target





config_reader = ConfigReader()
(   
    ACCESS_TOKEN_EXPIRE_MINUTES, 
    REFRESH_TOKEN_EXPIRE_DAYS, 
    JWT_SECRET_KEY, 
    JWT_ALGORITHM
) = config_reader.get_oauth_config()


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
    
    def get_host_by_hostname(self, hostname: str):   
        try:
            self._check_session()
            host = self.session.query(Host).filter(
                Host.hostname == hostname
            ).one_or_none()

            return host
        
        except Exception:
            raise

    def get_or_create_host(self, target_ip: str):
        _, hostname = normalize_target(target_ip)

        host = self.get_host_by_hostname(hostname)
        if not host:
            host = Host(
                hostname    = hostname,
                ip_address  = target_ip
            )
            self.session.add(host)
            self.session.flush()  
            self.logger.info(f"Se ha creado un host con id {host.id}")

        return host  

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
                self.logger.info(f"Escaneo {scan_id} encontrado")
            else:
                self.logger.warning(f"Escaneo {scan_id} no encontrado")
            
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
                return False

            numero = self.session.query(FinishedScan).filter(
                FinishedScan.id == scan_id
            ).count()
            is_finished = numero > 0
   
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

    def get_scan_status(self, scan_id: int) -> Optional[str]:
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

    @abstractmethod
    def _save_scan_results(self, scan: Scan, results: dict) -> None:
        pass


class OpenVASScanManager(ScanManager):
    """
    Gestor de escaneos OpenVAS que maneja la ejecución, monitoreo y 
    persistencia de análisis de vulnerabilidades.
    
    Attributes:
        username (str): Usuario para autenticación en OpenVAS
        password (str): Contraseña para autenticación
        hostname (str): Host del servidor OpenVAS
        port (str): Puerto del servidor OpenVAS
    """
    
    # Configuraciones predefinidas de escaneo
    SCAN_CONFIGS = {
        'full_fast': 'daba56c8-73ec-11df-a475-002264764cea',
        'full_deep': '8715c877-47a0-438d-98a3-27c7a6ab2196',
        'full_ultimate': '085569ce-73ed-11df-83c3-002264764cea'
    }
    
    PORT_LISTS = {
        'tcp_all': '33d0cd82-57c6-11e1-8ed1-406186ea4fc5',
        'tcp_udp_all': '4a4717fe-57d2-11e1-9a26-406186ea4fc5',
        'tcp_all_udp_top100': '730ef368-57e2-11e1-a90f-406186ea4fc5'
    }
    
    def __init__(self, user: User):
        """
        Inicializa el gestor de escaneos OpenVAS.
        
        Args:
            user (User): Usuario que ejecutará los escaneos
        """
        super().__init__(user)
        
        config = ConfigReader().get_openvas_config()["access"]
        self.username = config["username"]
        self.password = config["password"]
        self.hostname = config["hostname"]
        self.port = config["port"]
        
        self.logger.info("OpenVASScanManager inicializado")
    
    def run_scan(self, target: str, scan_config: str = 'full_fast') -> dict:
        """
        Ejecuta un escaneo OpenVAS completo de forma síncrona.
        
        Args:
            target_ip (str): IP o rango a escanear (ej: '192.168.1.1' o '192.168.1.0/24')
            scan_config (str): Tipo de configuración ('full_fast', 'full_deep', 'full_ultimate')
        
        Returns:
            dict: Resultado con 'success' (bool), 'scan' (OpenVASScan) o 'error' (str)
        """
        target_ip, _ = normalize_target(target)
        config_id = self.SCAN_CONFIGS.get(scan_config, self.SCAN_CONFIGS['full_fast'])
        result = self._launch_scan(target_ip, scan_config=config_id)
        
        if not result["success"]:
            self.logger.error(f"Error lanzando escaneo: {result.get('error')}")
            return result
        
        scan = result["scan"]
        
        try:
            report_data = self._get_scan_report_xml(
                task_id=scan.task_id,
                wait_for_completion=True
            )
            
            if not report_data["success"]:
                self.logger.error(f"Error obteniendo reporte: {report_data.get('message')}")
                return {"success": False, "error": report_data.get("message")}
            
            self._save_scan_results(scan)
            
            return {
                "success": True,
                "scan": scan,
                "message": "Escaneo completado exitosamente"
            }
            
        except Exception as e:
            self.logger.error(f"Error durante el escaneo: {str(e)}", exc_info=True)
            self._safe_rollback()
            return {"success": False, "error": str(e)}
    
    def get_scan_status(self, scan_id: int) -> Optional[dict]:
        """
        Obtiene el estado actual de un escaneo por ID.
        
        Args:
            scan_id (int): ID del escaneo en la base de datos
        
        Returns:
            Optional[dict]: Estado del escaneo con 'status' y 'progress', o None si no existe
        """
        scan = self.get_scan_by_id(scan_id)
        if not scan or not isinstance(scan, OpenVASScan):
            return None
        
        return self._get_task_status(scan.task_id)
    
    def _launch_scan(self, 
                    target_ip: str,
                    target_name: Optional[str] = None,
                    scan_config: str = 'daba56c8-73ec-11df-a475-002264764cea',
                    port_list_id: str = '33d0cd82-57c6-11e1-8ed1-406186ea4fc5',
                    reuse_target: bool = True) -> dict:
        """
        Lanza un escaneo en OpenVAS creando target y task necesarios.
        
        Args:
            target_ip: Dirección IP o rango a escanear
            target_name: Nombre descriptivo del objetivo (opcional)
            scan_config: UUID de la configuración de escaneo
            port_list_id: UUID de la lista de puertos
            reuse_target: Si True, reutiliza targets existentes
        
        Returns:
            dict: {'success': bool, 'scan': OpenVASScan} o {'success': bool, 'error': str}
        
        Raises:
            Exception: Si hay errores en la comunicación con OpenVAS
        """
        target_name = target_name or f"Target_{target_ip}"
        if not reuse_target:
            target_name = f"{target_name}_{int(time.time())}"
        
        try:
            connection = TLSConnection(hostname=self.hostname, port=self.port)
            
            with Gmp(connection=connection, transform=EtreeTransform()) as gmp:
                gmp.authenticate(self.username, self.password)
                self.logger.info(f"Autenticado en OpenVAS {self.hostname}:{self.port}")
                
                # Obtener o crear target
                target_id = self._get_or_create_target(
                    gmp, target_name, target_ip, port_list_id, reuse_target
                )
                
                # Obtener scanner por defecto
                scanner_id = self._get_default_scanner(gmp)
                
                # Crear y ejecutar tarea
                task_id, report_id = self._create_and_start_task(
                    gmp, target_name, target_ip, scan_config, target_id, scanner_id
                )
                
                # Crear registro en BD
                scan = self._create_scan_record(target_ip, task_id, report_id)
                
                return {'success': True, 'scan': scan}
                
        except Exception as e:
            self.logger.error(f"Error en _launch_scan: {str(e)}", exc_info=True)
            self._safe_rollback()
            return {'success': False, 'error': str(e)}
    
    def _get_scan_report_xml(self, 
                            task_id: str, 
                            wait_for_completion: bool = False,
                            check_interval: int = 10) -> dict:
        """
        Obtiene el reporte XML de un escaneo OpenVAS.
        
        Args:
            task_id: ID de la tarea en OpenVAS
            wait_for_completion: Si True, espera hasta que termine el escaneo
            check_interval: Segundos entre verificaciones (solo si wait_for_completion=True)
        
        Returns:
            dict: Contiene 'success', 'report_xml', 'status', 'progress', etc.
        """
        try:
            connection = TLSConnection(hostname=self.hostname, port=self.port)
            
            with Gmp(connection=connection, transform=EtreeTransform()) as gmp:
                gmp.authenticate(self.username, self.password)
                
                # Esperar finalización si se solicita
                if wait_for_completion:
                    task_info = self._wait_for_completion(gmp, task_id, check_interval)
                    if not task_info['completed']:
                        return task_info
                else:
                    task = gmp.get_task(task_id)
                    status = task.xpath('task/status')[0].text
                    progress = task.xpath('task/progress')[0].text
                    
                    if status not in ['Done', 'Stopped', 'Interrupted']:
                        return {
                            'success': False,
                            'completed': False,
                            'status': status,
                            'progress': f"{progress}%",
                            'message': f"Escaneo en progreso ({progress}%)"
                        }
                
                # Obtener reporte
                return self._extract_report(gmp, task_id)
                
        except Exception as e:
            self.logger.error(f"Error obteniendo reporte: {str(e)}", exc_info=True)
            return {'success': False, 'error': str(e)}
    
    def _save_scan_results(self, scan: OpenVASScan) -> None:
        """
        Procesa y guarda los resultados de un escaneo en la base de datos.
        
        Args:
            scan: Objeto OpenVASScan con task_id y report_id válidos
        
        Raises:
            SQLAlchemyError: Si hay errores de base de datos
        """
        try:
            # Obtener reporte XML
            report_data = self._get_scan_report_xml(
                task_id=scan.task_id,
                wait_for_completion=True
            )
            
            if not report_data.get("success"):
                raise Exception(f"No se pudo obtener reporte: {report_data.get('message')}")
            
            json_data = JSONManager.openvas_xml_to_json(report_data["report_xml"])
            vulnerability_map = self._process_vulnerabilities(json_data["vulnerabilities"])
            
            self._associate_host_to_scan(scan)
            self._create_scan_results(scan, json_data["scan_results"], vulnerability_map)
            self._mark_scan_finished(scan)
            
            self.logger.info(f"Escaneo {scan.id} guardado con {len(scan.results)} resultados")
            
        except Exception as e:
            self.logger.error(f"Error guardando resultados: {str(e)}", exc_info=True)
            self._safe_rollback()
            raise
    
    def _get_or_create_target(self, 
                              gmp: Gmp,
                              target_name: str,
                              target_ip: str,
                              port_list_id: str,
                              reuse: bool) -> str:
        """
        Obtiene un target existente o crea uno nuevo en OpenVAS.
        
        Args:
            gmp: Conexión GMP autenticada
            target_name: Nombre del target
            target_ip: IP del target
            port_list_id: ID de la lista de puertos
            reuse: Si True, intenta reutilizar target existente
        
        Returns:
            str: ID del target
        
        Raises:
            Exception: Si no se puede obtener o crear el target
        """
        target_id = None
        
        # Intentar reutilizar target existente
        if reuse:
            targets = gmp.get_targets(filter_string=f'name="{target_name}"')
            target_list = targets.xpath('target')
            if target_list:
                target_id = target_list[0].attrib.get('id')
                self.logger.info(f"Target reutilizado: {target_id}")
                return target_id
        
        # Crear nuevo target
        target_response = gmp.create_target(
            name=target_name,
            hosts=[target_ip],
            port_list_id=port_list_id,
            comment=f"Target creado para {target_ip}"
        )
        
        target_id = target_response.attrib.get('id') or target_response.get('id')
        
        if not target_id:
            raise Exception(f"No se pudo crear target. Response: {target_response.attrib}")
        
        self.logger.info(f"Target creado: {target_id}")
        return target_id
    
    def _get_default_scanner(self, gmp: Gmp) -> str:
        """
        Obtiene el ID del scanner OpenVAS por defecto.
        
        Args:
            gmp: Conexión GMP autenticada
        
        Returns:
            str: ID del scanner
        
        Raises:
            Exception: Si no se encuentra el scanner por defecto
        """
        scanners = gmp.get_scanners()
        
        for scanner in scanners.xpath('scanner'):
            if scanner.find('name').text == 'OpenVAS Default':
                scanner_id = scanner.get('id')
                self.logger.info(f"Scanner encontrado: {scanner_id}")
                return scanner_id
        
        raise Exception("No se encontró el scanner 'OpenVAS Default'")
    
    def _create_and_start_task(self,
                               gmp: Gmp,
                               target_name: str,
                               target_ip: str,
                               scan_config: str,
                               target_id: str,
                               scanner_id: str) -> Tuple[str, str]:
        """
        Crea una tarea de escaneo y la inicia inmediatamente.
        
        Args:
            gmp: Conexión GMP autenticada
            target_name: Nombre base para la tarea
            target_ip: IP objetivo
            scan_config: ID de configuración de escaneo
            target_id: ID del target
            scanner_id: ID del scanner
        
        Returns:
            Tuple[str, str]: (task_id, report_id)
        
        Raises:
            Exception: Si no se puede crear o iniciar la tarea
        """
        task_name = f"Scan_{target_name}_{int(time.time())}"
        
        task_response = gmp.create_task(
            name=task_name,
            config_id=scan_config,
            target_id=target_id,
            scanner_id=scanner_id,
            comment=f"Escaneo automático de {target_ip}"
        )
        
        task_id = task_response.attrib.get('id') or task_response.get('id')
        
        if not task_id:
            raise Exception(f"No se pudo crear tarea. Response: {task_response.attrib}")
        
        self.logger.info(f"Tarea creada: {task_id}")
        
        # Iniciar escaneo
        start_response = gmp.start_task(task_id)
        report_id = start_response.xpath('report_id')[0].text
        
        self.logger.info(f"Escaneo iniciado. Report ID: {report_id}")
        
        return task_id, report_id
    
    def _create_scan_record(self, target_ip: str, task_id: str, report_id: str) -> OpenVASScan:
        """
        Crea el registro del escaneo en la base de datos.
        
        Args:
            target_ip: IP objetivo del escaneo
            task_id: ID de la tarea en OpenVAS
            report_id: ID del reporte en OpenVAS
        
        Returns:
            OpenVASScan: Objeto de escaneo creado y persistido
        """
        scan = OpenVASScan(
            target=target_ip,
            user_id=self.active_user.id,
            task_id=task_id,
            report_id=report_id
        )
        
        self.session.add(scan)
        self.session.flush()
        
        self.logger.info(f"Registro de escaneo creado: {scan.id}")
        return scan
    
    def _wait_for_completion(self, 
                            gmp: Gmp,
                            task_id: str,
                            check_interval: int) -> dict:
        """
        Espera a que un escaneo complete, mostrando progreso.
        
        Args:
            gmp: Conexión GMP autenticada
            task_id: ID de la tarea
            check_interval: Segundos entre verificaciones
        
        Returns:
            dict: Información de finalización con 'completed', 'status', etc.
        """
        self.logger.info("Esperando finalización del escaneo...")
        
        while True:
            task = gmp.get_task(task_id)
            status = task.xpath('task/status')[0].text
            progress = task.xpath('task/progress')[0].text
            
            if status in ['Done', 'Stopped', 'Interrupted']:
                self.logger.info(f"Escaneo finalizado: {status}")
                return {'completed': True, 'status': status}
            
            self.logger.info(f"Estado: {status} - Progreso: {progress}%")
            time.sleep(check_interval)
    
    def _extract_report(self, gmp: Gmp, task_id: str) -> dict:
        """
        Extrae el reporte XML de un escaneo completado.
        
        Args:
            gmp: Conexión GMP autenticada
            task_id: ID de la tarea
        
        Returns:
            dict: Datos del reporte incluyendo 'report_xml', 'severity', etc.
        
        Raises:
            Exception: Si no se encuentra el reporte
        """
        task = gmp.get_task(task_id)
        last_report = task.xpath('task/last_report/report')[0]
        report_id = last_report.get('id')
        
        if not report_id:
            raise Exception("No se encontró reporte asociado")
        
        self.logger.info(f"Obteniendo reporte: {report_id}")
        
        # Obtener reporte completo
        report_response = gmp.get_report(
            report_id=report_id,
            report_format_id='a994b278-1f62-11e1-96ac-406186ea4fc5',  # XML format
            ignore_pagination=True,
            details=True
        )
        
        from lxml import etree
        report_xml = etree.tostring(report_response, encoding='unicode', pretty_print=True)
        
        severity = task.xpath('task/last_report/report/severity/text()')
        severity_value = severity[0] if severity else 'N/A'
        
        return {
            'success': True,
            'completed': True,
            'report_id': report_id,
            'task_id': task_id,
            'severity': severity_value,
            'report_xml': report_xml,
            'message': 'Reporte obtenido exitosamente'
        }
    
    def _get_task_status(self, task_id: str) -> Optional[dict]:
        """
        Consulta el estado de una tarea en OpenVAS.
        
        Args:
            task_id: ID de la tarea
        
        Returns:
            Optional[dict]: Estado con 'status' y 'progress', o None si hay error
        """
        try:
            connection = TLSConnection(hostname=self.hostname, port=self.port)
            
            with Gmp(connection=connection, transform=EtreeTransform()) as gmp:
                gmp.authenticate(self.username, self.password)
                
                task = gmp.get_task(task_id)
                status = task.xpath('task/status')[0].text
                progress = task.xpath('task/progress')[0].text
                
                return {
                    'success': True,
                    'status': status,
                    'progress': f"{progress}%"
                }
                
        except Exception as e:
            self.logger.error(f"Error obteniendo estado: {str(e)}")
            return None
    
    def _process_vulnerabilities(self, vulnerabilities_data: List[dict]) -> dict:
        """
        Procesa vulnerabilidades del reporte y las guarda en BD.
        
        Args:
            vulnerabilities_data: Lista de diccionarios con datos de vulnerabilidades
        
        Returns:
            dict: Mapeo de nvt_oid -> OpenVASVulnerability
        """
        vulnerability_map = {}
        
        for vuln_info in vulnerabilities_data:
            vuln = self._get_or_create_vulnerability(vuln_info)
            vulnerability_map[vuln.nvt_oid] = vuln
        
        return vulnerability_map
    
    def _get_or_create_vulnerability(self, vuln_data: dict) -> OpenVASVulnerability:
        """
        Obtiene una vulnerabilidad existente o crea una nueva.
        
        Args:
            vuln_data: Diccionario con datos de la vulnerabilidad
        
        Returns:
            OpenVASVulnerability: Objeto de vulnerabilidad
        """
        self._check_session()
        nvt_oid = vuln_data["nvt_oid"]
        
        # Buscar existente
        vuln = self.session.query(OpenVASVulnerability).filter(
            OpenVASVulnerability.nvt_oid == nvt_oid
        ).one_or_none()
        
        if vuln:
            return vuln
        
        # Crear nueva
        vuln = OpenVASVulnerability(
            nvt_oid=nvt_oid,
            name=vuln_data["name"],
            severity_score=vuln_data["severity_score"],
            severity_class=vuln_data["severity_class"],
            cvss_base_score=vuln_data["cvss_base_score"],
            cvss_vector=vuln_data["cvss_vector"],
            cve_ids=vuln_data["cve_ids"],
            cert_refs=vuln_data["cert_refs"],
            bugtraq_ids=vuln_data["bugtraq_ids"],
            other_refs=vuln_data["other_refs"],
            summary=vuln_data["summary"],
            description=vuln_data["description"],
            impact=vuln_data["impact"],
            insight=vuln_data["insight"],
            affected_software=vuln_data["affected_software"],
            solution_type=vuln_data["solution_type"],
            solution=vuln_data["solution"],
            qod_value=vuln_data["qod_value"],
            qod_type=vuln_data["qod_type"],
            family=vuln_data["family"],
            category=vuln_data["category"]
        )
        
        self.session.add(vuln)
        self.session.flush()
        
        self.logger.info(f"Vulnerabilidad creada: {nvt_oid}")
        return vuln
    
    def _associate_host_to_scan(self, scan: OpenVASScan) -> None:
        """
        Asocia un host al escaneo, creándolo si no existe.
        
        Args:
            scan: Objeto OpenVASScan a asociar
        """
        ip, hostname = normalize_target(scan.target)
        host = self.get_host_by_hostname(hostname)
        
        if not host:
            host = Host(
                hostname=hostname,
                ip_address=ip,
                mac_address="",  # OpenVAS puede no tener esta info
                vendor=""
            )
            self.session.add(host)
            self.session.flush()
        
        scan.host_id = host.id
        self.session.add(scan)
    
    def _create_scan_results(self,
                            scan: OpenVASScan,
                            results_data: List[dict],
                            vulnerability_map: dict) -> None:
        """
        Crea registros de resultados de escaneo asociando vulnerabilidades con hosts.
        
        Args:
            scan: Escaneo al que pertenecen los resultados
            results_data: Lista de resultados del escaneo
            vulnerability_map: Mapeo nvt_oid -> OpenVASVulnerability
        """
        for result in results_data:
            nvt_oid = result["nvt_oid"]
            host_ip = result["host_ip"]
            
            vulnerability = vulnerability_map[nvt_oid]
            host = self.get_or_create_host(host_ip)
            
            scan_result = OpenVASScanResult(
                openvas_scan_id=scan.id,
                vulnerability_id=vulnerability.id,
                host_id=host.id
            )
            
            self.session.add(scan_result)
        
        self.session.flush()
    
    def _mark_scan_finished(self, scan: OpenVASScan) -> None:
        """
        Marca un escaneo como finalizado en la base de datos.
        
        Args:
            scan: Escaneo a marcar como finalizado
        """
        finished = FinishedScan(
            id=scan.id,
            finished_at=datetime.now()
        )
        
        self.session.add(finished)
        self.session.flush()
        self._safe_commit()


class NmapScanManager(ScanManager):
    """
    Gestor completo para escaneos Nmap.
    Maneja tanto la ejecución de tareas como la persistencia.
    """
    
    def __init__(self, user: User, session=None):
        super().__init__(user, session)
        self.logger.info(f"NmapScanManager inicializado para usuario: {user.id}")

    def run_scan(self, target_host: str, target_ports: str, timeout: int = 120) -> int:
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
            
            nmap_scan = NmapScan(
                target=target_host,
                user=self.active_user,
                started_at=datetime.now()
            )
            
            self.session.add(nmap_scan)
            self._safe_commit()
            
            scan_id = nmap_scan.id
            self.logger.info(f"Escaneo Nmap {scan_id} creado, iniciando thread")
            
            thread = threading.Thread(
                target=self._execute_scan_thread,
                args=(scan_id, target_host, target_ports, timeout),
                daemon=False,
                name=f"NmapScan-{scan_id}"
            )
            thread.start()
            time.sleep(0.2)
            
            self.logger.info(f"Thread de escaneo Nmap {scan_id} iniciado")
            return scan_id # type: ignore
        
        except Exception as e:
            self.logger.error(f"Error al iniciar escaneo Nmap: {str(e)}", exc_info=True)
            raise
    
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
            
            task = NmapScanTask(target_host, target_ports, timeout=timeout)
            self.running_tasks[scan_id] = task
            
            task.scan()
            wait_timeout = timeout + 30
            success = task.wait(timeout=wait_timeout)
            
            if not success:
                thread_manager.logger.error(
                    f"Escaneo {scan_id} falló o excedió timeout. Estado: {task.status}"
                )
                scan.ended_at = datetime.now()
                thread_manager.session.add(scan)
                thread_manager._safe_commit()
                return
            
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
    
    def _save_scan_results(self, scan: Scan, results: dict) -> None:
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
                port_protocol, _, port_reason, port_product, port_product_version, given_use = port_data
                
                port = self._get_or_create_port(port_protocol)
                
                if port not in scan.target_ports:
                    scan.target_ports.append(port)
                
                open_port = OpenPort(
                    nmap_scan_id=scan.id,
                    port_id=port.id,
                    reason=port_reason,
                    product=port_product,
                    version=port_product_version,
                    given_use=given_use
                )
                self.session.add(open_port)

            host_info = processed_results["host"]
            hostname = host_info["name"]
            
            host = self.get_host_by_hostname(hostname=hostname)
            if host is None:
                host = Host(
                    hostname=host_info["name"],
                    vendor=host_info["vendor"],
                    ip_address=host_info["addresses"]["ipv4"],
                    mac_address=host_info["addresses"]["mac"]
                )
            
            self.session.add(host)
            scan.host_id = host.id
            self.session.add(scan)
            
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
            
            thread = threading.Thread(
                target=self._execute_scan_thread,
                args=(scan_id, target_domain, timeout),
                daemon=False,
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
            
            task.scan()
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
    
    def _save_scan_results(self, scan: Scan, results: dict) -> None:
        """Procesa y guarda los resultados del escaneo Nikto"""
        try:
            # Convertir resultados JSON
            processed_results = JSONManager.convert_json_to_individual_nikto_data(
                results[-1] if results else {}
            )

            self.logger.debug(processed_results)
            
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

            ip, hostname = normalize_target(scan.target) #type: ignore
            host = self.get_host_by_hostname(
                hostname=hostname # type: ignore
            )
            if host is None:
                host = Host(
                    hostname=hostname,
                    ip_address=ip
                )
                self.session.add(host)
                self.session.flush()
                self._safe_commit()

            scan.host = host
            self.session.add(scan)
            
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
            NiktoIncident.description == incident.description
        ).first()
        
        if existing:
            self.logger.debug(f"Incidente ya existe: {incident.description}")
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
    Gestor completo para usuarios y personas con autenticación y gestión de tokens.
    
    Características:
        - Autenticación con salt y hash
        - Gestión de usuarios y personas
        - Validación de credenciales
        - CRUD completo thread-safe
    """
    
    def verify_credentials(self, username: str, password: str) -> Tuple[bool, Optional[int]]:
        """
        Verifica las credenciales de un usuario.
        
        Args:
            username (str): Nombre de usuario
            password (str): Contraseña en texto plano
        
        Returns:
            Tuple[bool, Optional[int]]: (es_válido, user_id)
        """
        self._check_session()
        
        try:
            user = self._get_by_field(User, "username", username)
            
            if not user:
                self.logger.info(f"Usuario '{username}' no encontrado")
                return False, None
            
            valid_password = Encoder.verify_password(
                stored_hash=user.password_hash,
                password=password,
                salt=user.password_salt
            )
            
            if not valid_password:
                self.logger.warning(f"Contraseña incorrecta para '{username}'")
                return False, None
            
            user_id = user.id
            self.session.expunge(user)
            
            self.logger.info(f"Credenciales válidas para '{username}' (ID: {user_id})")
            return True, user_id
        
        except Exception as e:
            self.logger.error(f"Error verificando credenciales: {e}")
            raise
    
    def validate_credentials_simple(self, username: str, password: str) -> bool:
        """Validación simple de credenciales sin devolver user_id."""
        is_valid, _ = self.verify_credentials(username, password)
        return is_valid
    
    def create_user(self, user: User) -> None:
        """
        Crea un nuevo usuario.
        
        Args:
            user (User): Usuario a crear
        
        Raises:
            ExistingUserError: Si el usuario ya existe
        """
        self._check_session()
        
        try:
            if self._exists(User, "username", user.username):
                raise ExistingUserError(username=user.username)
            
            if user.person_id:
                if not self._exists(Person, "id", user.person_id):
                    if user.person:
                        self._create_person(user.person)
            elif user.person:
                self._create_person(user.person)
            
            self.session.add(user)
            self._safe_commit()
            
            self.logger.info(f"Usuario '{user.username}' creado con ID {user.id}")
        
        except ExistingUserError:
            raise
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error creando usuario: {e}")
            raise
    
    def sign_in_user(self, username: str, password: str, email: str, alias: str) -> User:
        """
        Registra un nuevo usuario vinculándolo a una persona.
        
        Args:
            username (str): Nombre de usuario
            password (str): Contraseña en texto plano
            email (str): Email del usuario
            alias (str): Alias de la persona existente
        
        Returns:
            User: Usuario creado
        
        Raises:
            ExistingUserError: Si el usuario ya existe
            UserBindingError: Si no existe la persona
        """
        self._check_session()
        
        try:
            if self._exists(User, "username", username):
                raise ExistingUserError(username)
            
            person = self._get_by_field(Person, "alias", alias)
            
            if not person:
                raise UserBindingError(username=username, alias=alias)
            
            salt = Encoder.generate_salt()
            hashed_password = Encoder.hash_password_with_salt(password, salt)
            
            new_user = User(
                username=username,
                password_hash=hashed_password,
                password_salt=salt,
                email=email,
                person_id=person.id
            )
            
            self.session.add(new_user)
            self._safe_commit()
            self.session.expunge(new_user)
            
            self.logger.info(f"Usuario '{username}' registrado exitosamente")
            return new_user
        
        except (ExistingUserError, UserBindingError):
            self._safe_rollback()
            raise
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error registrando usuario: {e}")
            raise DatabaseError("Error con credenciales. Revísalas e inténtalo de nuevo.")
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Obtiene un usuario por su username."""
        return self._get_by_field(User, "username", username)
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Obtiene un usuario por ID."""
        return self._get_by_field(User, "id", user_id)
    
    def get_all_users(self) -> List[User]:
        """Obtiene todos los usuarios."""
        return self._get_all(User)
    
    def update_user_password(self, user: User, new_password: str) -> None:
        """
        Actualiza la contraseña de un usuario.
        
        Args:
            user (User): Usuario a actualizar
            new_password (str): Nueva contraseña
        """
        self._check_session()
        
        try:
            new_salt = Encoder.generate_salt()
            new_hash = Encoder.hash_password_with_salt(new_password, new_salt)
            
            user.password_salt = new_salt
            user.password_hash = new_hash
            
            self.session.add(user)
            self._safe_commit()
            
            self.logger.info(f"Contraseña actualizada para usuario {user.id}")
        
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error actualizando contraseña: {e}")
            raise
    
    def update_user_password_by_id(self, user_id: int, new_password: str) -> None:
        """Actualiza la contraseña de un usuario por ID."""
        user = self.get_user_by_id(user_id)
        
        if not user:
            raise UserBindingError(username=str(user_id), alias="unknown")
        
        self.update_user_password(user, new_password)
    
    def delete_user(self, user: User) -> None:
        """Elimina un usuario."""
        self._delete(user, "Usuario")
    
    def sign_in_person(self, first_name: str, last_name: str, alias: str) -> Person:
        """
        Registra una nueva persona.
        
        Args:
            first_name (str): Nombre
            last_name (str): Apellido
            alias (str): Alias único
        
        Returns:
            Person: Persona creada
        
        Raises:
            ExistingUserError: Si ya existe
        """
        self._check_session()
        
        try:
            if self._exists(Person, "alias", alias):
                raise ExistingUserError(f"El alias {alias} ya está en uso")
            
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
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error registrando persona: {e}")
            raise
    
    def get_person_by_alias(self, alias: str) -> Optional[Person]:
        """Obtiene una persona por alias."""
        return self._get_by_field(Person, "alias", alias)
    
    def get_person_by_email(self, email: str) -> Optional[Person]:
        """Obtiene una persona por email."""
        return self._get_by_field(Person, "email", email)
    
    def get_person_by_id(self, person_id: int) -> Optional[Person]:
        """Obtiene una persona por ID."""
        return self._get_by_field(Person, "id", person_id)
    
    def get_all_people(self) -> List[Person]:
        """Obtiene todas las personas."""
        return self._get_all(Person)
    
    def update_person(self, person: Person) -> None:
        """Actualiza la información de una persona."""
        self._check_session()
        
        try:
            existing = self.get_person_by_id(person.id)
            
            if existing:
                existing.first_name = person.first_name
                existing.last_name = person.last_name
                existing.email = person.email
                
                self._safe_commit()
                self.logger.info(f"Persona {person.id} actualizada")
            else:
                self.logger.warning(f"Persona {person.id} no encontrada")
        
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error actualizando persona: {e}")
            raise
    
    def delete_person(self, person: Person) -> None:
        """Elimina una persona."""
        self._delete(person, "Persona")
    
    # Métodos privados genéricos
    
    def _get_by_field(self, model, field: str, value: Any) -> Optional[Any]:
        """
        Obtiene un objeto por un campo específico.
        
        Args:
            model: Clase del modelo
            field (str): Nombre del campo
            value: Valor a buscar
        
        Returns:
            Optional[Any]: Objeto encontrado o None
        """
        self._check_session()
        
        try:
            obj = self.session.query(model).filter(
                getattr(model, field) == value
            ).one_or_none()
            
            if obj:
                self.logger.debug(f"{model.__name__} con {field}='{value}' encontrado")
            else:
                self.logger.debug(f"{model.__name__} con {field}='{value}' no encontrado")
            
            return obj
        
        except Exception as e:
            self.logger.error(f"Error obteniendo {model.__name__}: {e}")
            raise
    
    def _get_all(self, model) -> List[Any]:
        """Obtiene todos los objetos de un modelo."""
        self._check_session()
        
        try:
            objects = self.session.query(model).all()
            self.logger.info(f"Se obtuvieron {len(objects)} {model.__name__}s")
            return objects
        
        except Exception as e:
            self.logger.error(f"Error obteniendo {model.__name__}s: {e}")
            raise
    
    def _exists(self, model, field: str, value: Any) -> bool:
        """Verifica si existe un objeto con el campo especificado."""
        self._check_session()
        
        exists = self.session.query(model).filter(
            getattr(model, field) == value
        ).count() > 0
        
        return exists
    
    def _delete(self, obj: Any, obj_type: str) -> None:
        """
        Elimina un objeto genérico.
        
        Args:
            obj: Objeto a eliminar
            obj_type (str): Tipo de objeto (para logging)
        """
        self._check_session()
        
        try:
            self.session.delete(obj)
            self._safe_commit()
            
            self.logger.info(f"{obj_type} eliminado")
        
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error eliminando {obj_type}: {e}")
            raise
    
    def _create_person(self, person: Person) -> None:
        """Crea una nueva persona (método interno)."""
        self._check_session()
        
        try:
            self.session.add(person)
            self.session.flush()
            self.logger.info(
                f"Persona creada: {person.first_name} {person.last_name} (ID: {person.id})"
            )
        
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error creando persona: {e}")
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