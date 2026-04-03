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
        """Obtiene o crea un host en la BD.

        Garantías:
        - hostname nunca es None (cae back a la IP o al target original).
        - ip_address nunca es None (cae back al target original).
        - mac_address se establece a cadena vacía si no está disponible, evitando
            NotNullViolation ya que la columna es NOT NULL en el modelo.
        """
        ip, hostname = normalize_target(target)
        self.logger.debug(f"Normalizando target '{target}' -> hostname: '{hostname}', ip: '{ip}'")

        # Fallbacks para evitar NOT NULL violations
        if not hostname:
            hostname = ip or target
        if not ip:
            ip = target

        host = self.session.query(Host).filter(
            Host.ip_address == ip,
            Host.hostname == hostname
        ).first()
            
        if not host:
            host = Host(
                hostname=hostname,
                ip_address=ip,
                mac_address="",   # NOT NULL en modelo; cadena vacía como nulo semántico
            )
            self.session.add(host)
            self.session.flush()
            self.logger.info(f"Host creado: {hostname} ({ip})")

        return host
    


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

        def assign_severity_to_nikto_incident(incident):
            desc = incident.description.lower() if incident.description else ""
            url = incident.url.lower() if incident.url else ""
            method = incident.method.upper() if incident.method else ""

            critical_patterns = [
                ".env", "env.production", "env.local", ".git/", ".git/config",
                "git/head", "phpinfo", "config.php", "database.yml", "wp-config.php",
                "web.config", ".sql", "backup.sql", "dump.sql", "passwd", "shadow",
                "credentials", "private_key", "id_rsa", "config.bak", "database.bak",
                "shell", "webshell", "backdoor", "remote code execution",
                "arbitrary code", "command injection", "sql injection",
                "unrestricted file upload",
            ]
            for pattern in critical_patterns:
                if pattern in desc or pattern in url:
                    incident.severity = "CRITICAL"
                    return

            high_patterns = [
                "outdated", "vulnerable version", "known vulnerability", "cve-",
                "xss", "cross site scripting", "cross-site scripting", "csrf",
                "authentication bypass", "authorization bypass", "privilege escalation",
                "directory traversal", "path traversal", "../", "local file inclusion",
                "remote file inclusion", "lfi", "rfi", "weak ssl", "weak tls",
                "ssl v2", "ssl v3", "sslv2", "sslv3", "poodle", "heartbleed",
                "shellshock", "default password", "default credential", "admin/admin",
                "weak cipher", "insecure cipher", "null cipher", "export cipher",
            ]
            dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]
            for pattern in high_patterns:
                if pattern in desc or pattern in url:
                    incident.severity = "HIGH"
                    return
            if method in dangerous_methods and "allowed" in desc:
                incident.severity = "HIGH"
                return

            medium_patterns = [
                "directory indexing", "directory listing", "indexes",
                "missing security header", "x-frame-options", "x-content-type-options",
                "content-security-policy", "strict-transport-security", "x-xss-protection",
                "clickjacking", "information disclosure", "information leakage",
                "stack trace", "error message", "debug mode", "verbose error",
                "source code disclosure", "path disclosure", "version disclosure",
                "session fixation", "weak session", "cookie without", "cookie httponly",
                "cookie secure", "unencrypted", "http basic auth", "weak authentication",
                "robots.txt", "sitemap.xml", "cors misconfiguration", "open redirect",
                "server-status", "server-info", "admin panel", "login panel",
                "phpmyadmin", "adminer",
            ]
            for pattern in medium_patterns:
                if pattern in desc or pattern in url:
                    incident.severity = "MEDIUM"
                    return

            low_patterns = [
                "server banner", "server header", "x-powered-by", "server version",
                "apache/", "nginx/", "microsoft-iis", "options method", "head method",
                "allowed http methods", "default page", "default installation",
                "test page", "welcome page", "it works", "uncommon header",
                "unusual header", "missing header", "cache control", "pragma",
                "expires", "retrieved x-powered-by", "retrieved server", "ip address",
                "internal ip", "retrieved via",
            ]
            for pattern in low_patterns:
                if pattern in desc or pattern in url:
                    incident.severity = "LOW"
                    return

            info_patterns = [
                "the site uses", "appears to be", "may be", "possibly",
                "cookie created", "retrieved", "hostname resolves", "scan completed",
                "target ip", "end time", "start time",
            ]
            for pattern in info_patterns:
                if pattern in desc:
                    incident.severity = "INFO"
                    return

            incident.severity = "MEDIUM"

        try:
            all_incidents = []
            for block in (results or []):
                block_incidents = JSONManager.convert_json_to_individual_nikto_data(block)
                all_incidents.extend(block_incidents)

            for incident_data in all_incidents:
                incident = self._create_incident_from_data(incident_data)
                assign_severity_to_nikto_incident(incident)
                db_incident = self._get_or_create_incident(incident)
                if db_incident not in scan.incidents:
                    scan.incidents.append(db_incident)

            self.logger.debug(f"Buscando o creando host para target '{scan.target}'")
            host = self._get_or_create_host(scan.target)
            self.logger.debug(f"Host asociado al escaneo Nikto {scan.id}: {host.hostname} ({host.ip_address})")
            scan.host = host
            self.logger.info(
                f"Escaneo Nikto {scan.id} guardado con {len(all_incidents)} incidentes"
            )

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
            NiktoIncident.description == incident.description,
            NiktoIncident.url == incident.url,
            NiktoIncident.method == incident.method,
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