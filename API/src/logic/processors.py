
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List

from sqlalchemy.orm import Session


from src.misc.inetutils import normalize_target
from src.misc.conversion import JSONManager
from src.core.model import (
    Host,
    Scan,
    OpenPort,
    Port,
    NiktoScan,
    NiktoIncident,
    NmapScan,
    OpenVASScan,
    OpenVASVulnerability,
    OpenVASScanResult
)


class ScanResultProcessor(ABC):
    """Clase base para procesadores de resultados de escaneos"""
    
    def __init__(self, session: Session, logger):
        self.session = session
        self.logger = logger
    
    @abstractmethod
    def process_and_save(self, scan, results: dict) -> None:
        """Procesa y guarda los resultados del escaneo"""
        pass
    
    def _get_or_create_host(self, target: str) -> Host:
        """Obtiene o crea un host en la BD"""
        ip, hostname = normalize_target(target)
        
        host = self.session.query(Host).filter(
            Host.hostname == hostname
        ).one_or_none()
        
        if not host:
            host = Host(hostname=hostname, ip_address=ip)
            self.session.add(host)
            self.session.flush()
            self.logger.info(f"Host creado: {hostname}")
        
        return host
    
    def _mark_scan_finished(self, scan_id: int) -> None:
        """Marca un escaneo como finalizado"""
        scan: Scan = self.session.get(Scan, scan_id)
        
        if scan is None:
            return
        
        scan.finished_at = datetime.now()
        self.session.add(scan)
        self.session.commit()



class NmapResultProcessor(ScanResultProcessor):
    """Procesa y guarda resultados de escaneos Nmap"""
    
    def process_and_save(self, scan: NmapScan, results: dict) -> None:
        """Procesa resultados de Nmap y los guarda en BD"""
        try:
            # Convertir resultados JSON
            processed = JSONManager.convert_json_to_individual_nmap_data(results, scan)
            
            # Guardar puertos
            for port_data in processed["ports"]:
                port_protocol, _, port_reason, port_product, port_version, given_use = port_data
                
                port = self._get_or_create_port(port_protocol)
                
                if port not in scan.target_ports:
                    scan.target_ports.append(port)
                
                open_port = OpenPort(
                    nmap_scan_id=scan.id,
                    port_id=port.id,
                    reason=port_reason,
                    product=port_product,
                    version=port_version,
                    given_use=given_use
                )
                self.session.add(open_port)
            
            # Asociar host
            host_info = processed["host"]
            host = self._get_or_create_host_from_data(host_info)
            scan.host_id = host.id
            
            # Marcar como finalizado
            self._mark_scan_finished(scan.id)
            
            self.logger.info(f"Escaneo Nmap {scan.id} guardado con {len(processed['ports'])} puertos")
        
        except Exception as e:
            self.logger.error(f"Error guardando resultados Nmap: {e}", exc_info=True)
            raise
    
    def _get_or_create_port(self, protocol: str) -> Port:
        """Obtiene o crea un puerto"""
        port = self.session.query(Port).filter(Port.protocol == protocol).one_or_none()
        
        if port:
            return port
        
        new_port = Port(protocol=protocol)
        self.session.add(new_port)
        self.session.flush()
        return new_port
    
    def _get_or_create_host_from_data(self, host_info: dict) -> Host:
        """Crea o actualiza un host con información completa"""
        hostname = host_info["name"]
        
        host = self.session.query(Host).filter(
            Host.hostname == hostname
        ).one_or_none()
        
        if not host:
            host = Host(
                hostname=hostname,
                vendor=host_info["vendor"],
                ip_address=host_info["addresses"]["ipv4"],
                mac_address=host_info["addresses"]["mac"]
            )
            self.session.add(host)
            self.session.flush()
        
        return host


class NiktoResultProcessor(ScanResultProcessor):
    """Procesa y guarda resultados de escaneos Nikto"""
    
    def process_and_save(self, scan: NiktoScan, results: dict) -> None:
        """Procesa resultados de Nikto y los guarda en BD"""

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


        try:
            # Convertir resultados JSON
            processed = JSONManager.convert_json_to_individual_nikto_data(
                results[-1] if results else {}
            )
            
            # Guardar incidentes
            for incident_data in processed:
                incident = self._create_incident_from_data(incident_data)
                assign_severity_to_nikto_incident(incident)
                
                db_incident = self._get_or_create_incident(incident)
                
                if db_incident not in scan.incidents:
                    scan.incidents.append(db_incident)
            
            # Asociar host
            host = self._get_or_create_host(scan.target)
            scan.host = host
            
            # Marcar como finalizado
            self._mark_scan_finished(scan.id)
            
            self.logger.info(f"Escaneo Nikto {scan.id} guardado con {len(processed)} incidentes")
        
        except Exception as e:
            self.logger.error(f"Error guardando resultados Nikto: {e}", exc_info=True)
            raise
    
    def _create_incident_from_data(self, incident_data: dict) -> NiktoIncident:
        """Crea un objeto NiktoIncident desde datos procesados"""
        incident = NiktoIncident()
        incident.description = incident_data["description"]
        incident.osvdb_id = incident_data["osvdbid"]
        incident.method = incident_data["method"]
        incident.url = incident_data["uri"]
        return incident
    
    def _get_or_create_incident(self, incident: NiktoIncident) -> NiktoIncident:
        """Obtiene o crea un incidente en BD"""
        existing = self.session.query(NiktoIncident).filter(
            NiktoIncident.description == incident.description
        ).first()
        
        if existing:
            return existing
        
        self.session.add(incident)
        self.session.flush()
        return incident
    

class OpenVASResultProcessor(ScanResultProcessor):
    """Procesa y guarda resultados de escaneos OpenVAS"""
    
    def process_and_save(self, scan: OpenVASScan, results: dict) -> None:
        """Procesa resultados de OpenVAS y los guarda en BD"""
        try:
            # Procesar vulnerabilidades
            vulnerability_map = self._process_vulnerabilities(results["vulnerabilities"])
            
            # Asociar host
            host = self._get_or_create_host(scan.target)
            scan.host_id = host.id
            
            # Crear resultados de escaneo
            self._create_scan_results(scan, results["scan_results"], vulnerability_map)
            
            # Marcar como finalizado
            self._mark_scan_finished(scan.id)
            
            self.logger.info(f"Escaneo OpenVAS {scan.id} guardado con {len(scan.results)} resultados")
        
        except Exception as e:
            self.logger.error(f"Error guardando resultados OpenVAS: {e}", exc_info=True)
            raise
    
    def _process_vulnerabilities(self, vulnerabilities_data: List[dict]) -> dict:
        """Procesa y guarda vulnerabilidades"""
        vulnerability_map = {}
        
        for vuln_data in vulnerabilities_data:
            vuln = self._get_or_create_vulnerability(vuln_data)
            vulnerability_map[vuln.nvt_oid] = vuln
        
        return vulnerability_map
    
    def _get_or_create_vulnerability(self, vuln_data: dict) -> OpenVASVulnerability:
        """Obtiene o crea una vulnerabilidad"""
        nvt_oid = vuln_data["nvt_oid"]
        
        vuln = self.session.query(OpenVASVulnerability).filter(
            OpenVASVulnerability.nvt_oid == nvt_oid
        ).one_or_none()
        
        if vuln:
            return vuln
        
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
        return vuln
    
    def _create_scan_results(
        self,
        scan: OpenVASScan,
        results_data: List[dict],
        vulnerability_map: dict
    ) -> None:
        """Crea registros de resultados asociando vulnerabilidades con hosts"""
        for result in results_data:
            nvt_oid = result["nvt_oid"]
            host_ip = result["host_ip"]
            
            vulnerability = vulnerability_map[nvt_oid]
            host = self._get_or_create_host(host_ip)
            
            scan_result = OpenVASScanResult(
                openvas_scan_id=scan.id,
                vulnerability_id=vulnerability.id,
                host_id=host.id
            )
            
            self.session.add(scan_result)
        
        self.session.flush()