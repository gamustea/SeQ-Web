import subprocess
import threading
import re
import time

from urllib.parse import urlparse
from datetime import datetime
from pathlib import Path
from typing import Optional, Any, List, Dict
from enum import Enum, auto
from abc import ABC, abstractmethod
from nmap import PortScanner

from src.misc import (
    ConfigReader, 
    DirectoryType, 
    SecOpsLogger,
    DirectoryChecker,
    PlatformDetector
)

import xml.etree.ElementTree as ET
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.protocols.gmp.requests.v226 import AliveTest


class TaskStatus(Enum):
    """
    Enum que representa los diferentes estados en los que puede estar una tarea de escaneo.
    """
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    
    def __str__(self):
        return self.value


class _Task(ABC):
    """
    Clase base abstracta para representar una tarea de escaneo.
    """
    timout: int
    statis: TaskStatus = TaskStatus.PENDING
    target: str
    config_reader: ConfigReader = ConfigReader()
    logger = SecOpsLogger(name=__name__).get_logger()
    progress: int = 0

    def __init__(self, target: str, timeout: int = 200000):
        self.timeout = timeout
        self.results: Optional[Any] = None
        self.target: str = target
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._finished = threading.Event()
        self._started = threading.Event()
        self._cancel_event = threading.Event()
        self._output_file: Optional[Path] = None

    @abstractmethod
    def _build_command(self) -> List[str]:
        """Construye el comando a ejecutar."""
        pass

    @abstractmethod
    def _process_results(self) -> None:
        """Procesa los resultados del escaneo."""
        pass

    def _parse_progress(self, line: str) -> int:
        """
        Extrae el porcentaje de progreso de una línea de salida.
        """
        match = re.search(r'(\d+(?:\.\d+)?)%', line)
        if match:
            prog_float = float(match.group(1))
            if 0 <= prog_float <= 100:
                return int(round(prog_float))
        return -1

    def _read_output(self):
        """
        Lee la salida del proceso en un thread separado.
        """
        try:
            self._started.set()
            output_lines = []
            while True:
                if self._proc is None or self._proc.stdout is None:
                    break
                line = self._proc.stdout.readline()
                if not line:
                    break
                self.logger.debug(f"Output: {line.strip()}")
                output_lines.append(line)

                # Detectar que Nikto imprimió el help (opción inválida)
                if "Unknown option:" in line or "requires a value" in line:
                    self.logger.error(
                        f"Nikto rechazó el comando (opción inválida): {line.strip()}"
                    )
                    self.status = TaskStatus.FAILED

                prog = self._parse_progress(line)
                if prog != -1:
                    with self._lock:
                        self.progress = prog
        
        except Exception as e:
            self.logger.error(f"Error leyendo salida: {e}")
        
        finally:
            # Esperar a que el proceso termine completamente
            if self._proc:
                try:
                    self._proc.wait(timeout=10)
                    self.logger.debug(f"Proceso terminó con código: {self._proc.returncode}")
                except subprocess.TimeoutExpired:
                    self.logger.error("Timeout esperando fin del proceso")
                    self._proc.kill()
                    self._proc.wait()
            
            # Dar tiempo al sistema de archivos para escribir completamente
            time.sleep(0.5)
            
            # Señalizar que todo terminó
            self._finished.set()

    def scan(self) -> None:
        """Inicia el escaneo de forma ASÍNCRONA."""
        if self._proc and self._proc.poll() is None:
            self.logger.warning("El escaneo ya está en ejecución")
            return
        
        try:
            self.status = TaskStatus.RUNNING
            cmd = self._build_command()
            self.logger.info(f"Iniciando escaneo con comando: {' '.join(cmd)}")
            
            if self._output_file and not self._output_file.parent.exists():
                self._output_file.parent.mkdir(parents=True, exist_ok=True)
            
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Verificar que el proceso inició
            time.sleep(0.1)
            returncode = self._proc.poll()
            
            # ✅ MEJORADO: Solo fallar si hay código de error real
            if returncode is not None and returncode != 0:
                self.status = TaskStatus.FAILED
                raise RuntimeError(f"Proceso falló al iniciar (código {returncode})")
            
            # ⚠️ Si terminó con código 0, dejar que wait() lo maneje
            if returncode == 0:
                self.logger.warning(f"Proceso terminó inmediatamente con código 0. Puede que el target no sea alcanzable.")
            
            # Iniciar thread de lectura
            self._thread = threading.Thread(target=self._read_output, daemon=True)
            self._thread.start()
            
            if not self._started.wait(timeout=5):
                raise RuntimeError("Thread de lectura no inició")
            
            self.logger.info("Escaneo iniciado correctamente (no bloqueante)")
        
        except Exception as e:
            self.status = TaskStatus.FAILED
            self.logger.error(f"Error iniciando escaneo: {e}")
            raise

    def wait(self, timeout: Optional[float] = None) -> bool:
        """
        Espera a que termine el escaneo.
        Esta es la llamada BLOQUEANTE que debe usar el thread worker.
        """
        try:
            # Verificar que scan() se llamó
            if not self._started.is_set():
                self.logger.error("wait() llamado pero scan() nunca se ejecutó")
                return False

            # Esperar a que termine
            finished = self._finished.wait(timeout)
            if not finished:
                self.status = TaskStatus.TIMEOUT
                self.logger.error("Timeout agotado")
                if self._proc and self._proc.poll() is None:
                    self._proc.kill()
                    self._proc.wait()
                return False

            if self.status in (TaskStatus.CANCELLED,
                            TaskStatus.TIMEOUT,
                            TaskStatus.FAILED):
                self.logger.info(f"wait() termina con estado {self.status.value}")
                return self.status == TaskStatus.COMPLETED


            if self._proc:
                if self._proc.returncode != 0:
                    self.status = TaskStatus.FAILED
                    self.logger.error(
                        f"Proceso terminó con error: código {self._proc.returncode}"
                    )
                    return False

            if self._output_file and not self._output_file.exists():
                self.status = TaskStatus.FAILED
                self.logger.error(f"Archivo de salida no existe: {self._output_file}")
                return False

            # Verificar que existe el archivo de salida
            if self._output_file and not self._output_file.exists():
                self.status = TaskStatus.FAILED
                self.logger.error(f"Archivo de salida no existe: {self._output_file}")
                return False

            # Verificar que el archivo no está vacío
            if self._output_file and self._output_file.stat().st_size == 0:
                self.status = TaskStatus.FAILED
                self.logger.error(f"Archivo de salida está vacío: {self._output_file}")
                return False

            # Procesar resultados
            self._process_results()

            # Verificar que se obtuvieron resultados
            if self.results is None:
                self.status = TaskStatus.FAILED
                self.logger.error("No se pudieron procesar los resultados")
                return False

            # Todo OK
            self.status = TaskStatus.COMPLETED
            self.progress = 100
            self.logger.info("Escaneo completado correctamente")
            return True

        except Exception as e:
            self.status = TaskStatus.FAILED
            self.logger.error(f"Error en wait: {e}", exc_info=True)
            return False

    def is_finished(self) -> bool:
        """Indica si la tarea ha finalizado."""
        return self._finished.is_set()

    def cancel(self) -> None:
        """Cancela el escaneo."""
        # Marcar que se ha solicitado cancelación (lo usará OpenVAS, etc.)
        self._cancel_event.set()

        # Si es un escaneo basado en proceso, terminarlo
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.logger.warning("terminate() no fue suficiente, haciendo kill()")
                self._proc.kill()
                self._proc.wait()

        # Estado final de cancelación
        self.status = TaskStatus.CANCELLED
        self._finished.set()
        self.logger.info("Escaneo cancelado")

    def get_status_string(self) -> str:
        """Obtiene el estado como string."""
        return self.status.value


class NmapScanTask(_Task):
    """
    Implementación concreta para escaneos Nmap.
    """

    def __init__(self, target_host="127.0.0.1", target_ports="1-6000", timeout: int = 300):
        super().__init__(target_host, timeout)
        TEMP_DIR = ConfigReader().get_directory_of(DirectoryType.TEMP)
        
        timestamp = int(time.time() * 1000)
        safe_target = target_host.replace("/", "_").replace(":", "_")
        FILE_NAME = f"nmap_scan_{safe_target}_{timestamp}.xml"
        
        self.target_ports = target_ports
        self._output_file = Path(f"{TEMP_DIR}/{FILE_NAME}")
        self.scanner = None
        self.platform = PlatformDetector()
        
        self._output_file.parent.mkdir(parents=True, exist_ok=True)

    def _build_command(self) -> List[str]:
        nmap_cmd = [
            "sudo", "-n", "nmap",
            "-sV", "-sT",
            "-p", self.target_ports,
            "-oX", str(self._output_file),
            self.target,
            "--stats-every", "1s"
        ]

        if self.platform.is_windows and self.platform.wsl_available:
            wsl_output = self.platform.convert_path_to_wsl(str(self._output_file))
            nmap_cmd = [
                "sudo", "-n", "nmap",
                "-sV", "-sT",
                "-p", self.target_ports,
                "-oX", wsl_output,
                self.target,
                "--stats-every", "1s"
            ]
            return self.platform.wrap_wsl_command(nmap_cmd)

        return nmap_cmd

    def _process_results(self) -> None:
        try:
            if not self._output_file.exists():
                self.logger.error(f"Archivo XML no existe: {self._output_file}")
                self.results = None
                return
            if self._output_file.stat().st_size == 0:
                self.logger.error(f"Archivo XML está vacío: {self._output_file}")
                self.results = None
                return

            with self._output_file.open("r", encoding="utf-8") as f:
                xml_data = f.read()

            if not xml_data.strip():
                self.logger.error("Contenido del XML está vacío")
                self.results = None
                return

            self.results = self._parse_nmap_xml(xml_data)
            self.logger.info(f"Resultados procesados: {self._output_file}")

        except Exception as e:
            self.logger.error(f"Error procesando resultados: {e}", exc_info=True)
            self.results = None
            raise

    def _parse_nmap_xml(self, xml_data: str) -> dict:
        """
        Parsea el XML de nmap reproduciendo exactamente la estructura
        que devuelve PortScanner.analyse_nmap_xml_scan(), que es lo que
        espera JSONManager.convert_json_to_individual_nmap_data().
        Estructura devuelta:
        {
            "nmap": {"command_line": "...", "scaninfo": {...}, ...},
            "scan": {
                "192.168.1.1": {
                    "hostnames": [{"name": "...", "type": "..."}],
                    "addresses": {"ipv4": "...", "mac": "..."},
                    "vendor": {"MAC": "vendor"},
                    "status": {"state": "up", "reason": "..."},
                    "tcp": {
                        80: {"state": "open", "reason": "...", "name": "http",
                            "product": "...", "version": "...", "extrainfo": "...",
                            "conf": "...", "cpe": ""}
                    }
                }
            },
            "stats": {"timestr": "...", "elapsed": "...", "uphosts": "1", ...}
        }
        """
        root = ET.fromstring(xml_data)

        # ── Metadatos del escaneo ──────────────────────────────────────────────
        nmap_meta = {
            "command_line": root.get("args", ""),
            "version": root.get("version", ""),
            "scanflags": "",
            "scaninfo": {}
        }
        scaninfo_el = root.find("scaninfo")
        if scaninfo_el is not None:
            nmap_meta["scaninfo"] = {
                "type": scaninfo_el.get("type", ""),
                "protocol": scaninfo_el.get("protocol", ""),
                "numservices": scaninfo_el.get("numservices", ""),
                "services": scaninfo_el.get("services", ""),
            }

        # ── Stats ──────────────────────────────────────────────────────────────
        stats = {}
        runstats = root.find("runstats")
        if runstats is not None:
            finished = runstats.find("finished")
            hosts_el = runstats.find("hosts")
            stats = {
                "timestr": finished.get("timestr", "") if finished is not None else "",
                "elapsed": finished.get("elapsed", "") if finished is not None else "",
                "uphosts": hosts_el.get("up", "0") if hosts_el is not None else "0",
                "downhosts": hosts_el.get("down", "0") if hosts_el is not None else "0",
                "totalhosts": hosts_el.get("total", "0") if hosts_el is not None else "0",
            }

        # ── Hosts ──────────────────────────────────────────────────────────────
        scan = {}
        for host in root.findall("host"):
            # Dirección IP principal
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host.find("address")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "unknown")

            # Todas las direcciones (ipv4, mac...)
            addresses = {}
            vendor = {}
            for a in host.findall("address"):
                atype = a.get("addrtype", "")
                addr_val = a.get("addr", "")
                addresses[atype] = addr_val
                if atype == "mac" and a.get("vendor"):
                    vendor[addr_val] = a.get("vendor", "")

            # Estado
            status_el = host.find("status")
            status = {
                "state": status_el.get("state", "unknown") if status_el is not None else "unknown",
                "reason": status_el.get("reason", "") if status_el is not None else "",
            }

            # Hostnames
            hostnames = []
            hostnames_el = host.find("hostnames")
            if hostnames_el is not None:
                for hn in hostnames_el.findall("hostname"):
                    hostnames.append({
                        "name": hn.get("name", ""),
                        "type": hn.get("type", ""),
                    })
            # Si no hay hostname, usar la IP
            if not hostnames:
                hostnames.append({"name": ip, "type": "PTR"})

            # Puertos TCP y UDP
            tcp_ports = {}
            udp_ports = {}
            ports_el = host.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    proto = port_el.get("protocol", "tcp")
                    portid = int(port_el.get("portid", 0))
                    state_el = port_el.find("state")
                    service_el = port_el.find("service")

                    port_data = {
                        "state": state_el.get("state", "") if state_el is not None else "",
                        "reason": state_el.get("reason", "") if state_el is not None else "",
                        "name": service_el.get("name", "") if service_el is not None else "",
                        "product": service_el.get("product", "") if service_el is not None else "",
                        "version": service_el.get("version", "") if service_el is not None else "",
                        "extrainfo": service_el.get("extrainfo", "") if service_el is not None else "",
                        "conf": service_el.get("conf", "") if service_el is not None else "",
                        "cpe": "",
                    }
                    cpe_el = service_el.find("cpe") if service_el is not None else None
                    if cpe_el is not None and cpe_el.text:
                        port_data["cpe"] = cpe_el.text

                    if proto == "tcp":
                        tcp_ports[portid] = port_data
                    else:
                        udp_ports[portid] = port_data

            scan[ip] = {
                "hostnames": hostnames,
                "addresses": addresses,
                "vendor": vendor,
                "status": status,
                "tcp": tcp_ports,
                "udp": udp_ports,
            }

        return {"nmap": nmap_meta, "scan": scan, "stats": stats}


class NiktoScanTask(_Task):
    """
    Implementación concreta para escaneos Nikto.
    """

    def __init__(self, target_domain, timeout: int = 120):
        super().__init__(target_domain, timeout)
        
        timestamp = int(time.time() * 1000)
        self.temp_path = DirectoryChecker().verify_directory(DirectoryType.TEMP) / f"nikto_scan_{timestamp}.xml"
        self._output_file = self.temp_path
        self.platform = PlatformDetector()

    def _build_command(self) -> List[str]:
        raw = self.target
        if "://" not in raw:
            raw = "http://" + raw

        parsed = urlparse(raw)
        host = parsed.hostname or self.target
        scheme = (parsed.scheme or "http").lower()
        use_ssl = scheme == "https"
        port = parsed.port or (443 if use_ssl else 80)

        nikto_cmd = [
            "nikto",
            "-h", host,
            "-port", str(port),
            "-output", str(self.temp_path),
            "-Format", "xml",
            "-Tuning", "1234569b",
            "-timeout", "10",
            "-nointeractive",
        ]

        if use_ssl:
            nikto_cmd.append("-ssl")

        if self.platform.is_windows and self.platform.wsl_available:
            wsl_path = self.platform.convert_path_to_wsl(str(self.temp_path))
            nikto_cmd = [
                "nikto",
                "-h", host,
                "-port", str(port),
                "-output", wsl_path,
                "-Format", "xml",
                "-Tuning", "1234569b",
                "-timeout", "10",
                "-nointeractive",
            ]
            if use_ssl:
                nikto_cmd.append("-ssl")
            return self.platform.wrap_wsl_command(nikto_cmd)

        return nikto_cmd

    def _parse_nikto_xml(self, xml_path: str) -> List[Dict]:
        """Parsea archivo XML de Nikto a lista de diccionarios."""
        import xmltodict
        import re
        
        xml_file = Path(xml_path)
        if not xml_file.is_file():
            return []
        
        try:
            content = xml_file.read_text(encoding='utf-8')
            # Nikto puede generar múltiples bloques <niktoscan>
            pattern = re.compile(r'(<niktoscan.*?>.*?</niktoscan>)', re.DOTALL)
            matches = pattern.findall(content)
            
            if not matches:
                return []
            
            results = []
            for match in matches:
                doc_dict = xmltodict.parse(match)
                results.append(doc_dict)
            return results
            
        except Exception as e:
            self.logger.error(f"Error parseando XML Nikto: {e}")
            return []

    def _process_results(self) -> None:
        """Procesa el XML generado por Nikto."""
        try:
            if not self.temp_path.exists():
                self.logger.error(f"Archivo XML no existe: {self.temp_path}")
                self.results = None
                return
            
            if self.temp_path.stat().st_size == 0:
                self.logger.error(f"Archivo XML está vacío: {self.temp_path}")
                self.results = None
                return
            
            # REEMPLAZAR: JSONManager.convert_multi_niktoscan_xml_to_json
            self.results = self._parse_nikto_xml(str(self.temp_path))
            self.logger.info("Resultados Nikto procesados")
        
        except Exception as e:
            self.logger.error(f"Error procesando resultados Nikto: {e}", exc_info=True)
            self.results = None
            raise


class OpenVASTask(_Task):
    """
    Tarea de escaneo OpenVAS que maneja la conexión con el servidor GVM.
    A diferencia de Nmap/Nikto, esta tarea NO ejecuta comandos CLI sino que
    usa la API de OpenVAS mediante GMP.
    """
    
    def __init__(
        self, 
        target: str,
        hostname: str,
        port: str,
        username: str,
        password: str,
        scan_config: str = 'daba56c8-73ec-11df-a475-002264764cea',
        port_list_id: str = '33d0cd82-57c6-11e1-8ed1-406186ea4fc5',
        timeout: int = 14400
    ):
        super().__init__(target, timeout)
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.scan_config = scan_config
        self.port_list_id = port_list_id
        
        self.task_id: Optional[str] = None
        self.report_id: Optional[str] = None
        self._report_xml: Optional[str] = None
    
    def _build_command(self) -> List[str]:
        """OpenVAS no usa comandos CLI, retorna lista vacía"""
        return []
    
    def scan(self) -> None:
        """
        Inicia el escaneo OpenVAS de forma asíncrona.
        Override del método base porque OpenVAS funciona diferente.
        """
        try:
            self.status = TaskStatus.RUNNING
            self._started.set()
            
            # Lanzar escaneo en thread separado
            self._thread = threading.Thread(target=self._execute_openvas_scan, daemon=True)
            self._thread.start()
            
            self.logger.info(f"Escaneo OpenVAS iniciado para {self.target}")
        
        except Exception as e:
            self.status = TaskStatus.FAILED
            self.logger.error(f"Error iniciando escaneo OpenVAS: {e}")
            raise
    
    def _execute_openvas_scan(self) -> None:
        try:
            # Fase 1: setup (conexión corta)
            with self._create_gmp_connection() as gmp:
                gmp.authenticate(self.username, self.password)
                target_id = self._get_or_create_target(gmp)
                scanner_id = self._get_default_scanner(gmp)
                self._create_and_start_task(gmp, target_id, scanner_id)

            # Fase 2: polling largo (reconecta cada vez)
            self._wait_for_completion()

            if self.status == TaskStatus.CANCELLED:
                self._finished.set()
                return

            # Fase 3: obtener reporte (conexión corta)
            with self._create_gmp_connection() as gmp:
                gmp.authenticate(self.username, self.password)
                self._fetch_report(gmp)

            self._finished.set()

        except Exception as e:
            self.status = TaskStatus.FAILED
            self.logger.error(f"Error en escaneo OpenVAS: {e}", exc_info=True)
            self._finished.set()
    
    def _get_or_create_target(self, gmp: Gmp) -> str:
        target_name = f"Target_{self.target}"
        
        targets = gmp.get_targets(filter_string=f'name="{target_name}"')
        target_list = targets.xpath('target')
        
        if target_list:
            target_id = target_list[0].attrib.get('id')
            self.logger.info(f"Reutilizando target: {target_id}")
            return target_id
        
        self.logger.info(f"Creando target con CONSIDER_ALIVE para {self.target}")
        
        target_response = gmp.create_target(
            name=target_name,
            hosts=[self.target],
            port_list_id=self.port_list_id,
            comment=f"Target para {self.target}",
            alive_test=AliveTest.CONSIDER_ALIVE
        )
        
        try:
            from lxml import etree
            self.logger.info(f"[DEBUG] create_target response: {etree.tostring(target_response, encoding='unicode')}")
        except Exception:
            pass
        
        target_id = target_response.attrib.get('id') or target_response.get('id')
        self.logger.info(f"Target creado con id: {target_id}")
        return target_id
    
    def _get_default_scanner(self, gmp: Gmp) -> str:
        """Obtiene el scanner por defecto de OpenVAS"""
        scanners = gmp.get_scanners()
        
        for scanner in scanners.xpath('scanner'):
            if scanner.find('name').text == 'OpenVAS Default':
                scanner_id = scanner.get('id')
                self.logger.info(f"Scanner encontrado: {scanner_id}")
                return scanner_id
        
        raise RuntimeError("No se encontró el scanner 'OpenVAS Default'")
    
    def _create_and_start_task(self, gmp: Gmp, target_id: str, scanner_id: str) -> None:
        task_name = f"Scan_{self.target}_{int(time.time())}"

        task_response = gmp.create_task(
            name=task_name,
            config_id=self.scan_config,
            target_id=target_id,
            scanner_id=scanner_id,
            comment=f"Escaneo de {self.target}"
        )

        # Intento 1: atributo directo en el elemento raíz
        self.task_id = task_response.get('id')

        # Intento 2: xpath @id
        if not self.task_id:
            ids = task_response.xpath('@id')
            self.task_id = ids[0] if ids else None

        # Intento 3: subelemento <id>
        if not self.task_id:
            id_el = task_response.find('id')
            self.task_id = id_el.text.strip() if id_el is not None and id_el.text else None

        # Intento 4: atributo en subelemento <task>
        if not self.task_id:
            task_el = task_response.find('task')
            self.task_id = task_el.get('id') if task_el is not None else None

        if not self.task_id:
            try:
                from lxml import etree
                self.logger.error(
                    f"[DEBUG] create_task response: {etree.tostring(task_response, encoding='unicode')}"
                )
            except Exception:
                self.logger.error(f"[DEBUG] create_task response attrib: {dict(task_response.attrib)}")
            raise RuntimeError("No se pudo obtener el task_id de la respuesta de create_task")

        self.logger.info(f"Tarea creada: {self.task_id}")

        start_response = gmp.start_task(self.task_id)
        self.report_id = start_response.xpath('report_id')[0].text
        self.logger.info(f"Escaneo iniciado. Report ID: {self.report_id}")
    
    def _wait_for_completion(self, check_interval: int = 60) -> None:
        """Espera a que el escaneo complete reconectando en cada iteración."""
        while True:
            if self._cancel_event.is_set():
                # Abrir conexión puntual solo para detener la tarea
                with self._create_gmp_connection() as gmp:
                    gmp.authenticate(self.username, self.password)
                    try:
                        gmp.stop_task(self.task_id)
                    except Exception as e:
                        self.logger.error(f"Error deteniendo tarea: {e}")
                self.status = TaskStatus.CANCELLED
                break

            try:
                # Conexión nueva en cada poll → nunca expira por tiempo
                with self._create_gmp_connection() as gmp:
                    gmp.authenticate(self.username, self.password)
                    task = gmp.get_task(self.task_id)
            except Exception as e:
                self.logger.warning(f"Error consultando tarea, reintentando en {check_interval}s: {e}")
                time.sleep(check_interval)
                continue

            status = task.xpath('task/status')[0].text
            progress_text = task.xpath('task/progress')[0].text

            with self._lock:
                self.progress = int(float(progress_text))

            self.logger.info(f"Estado: {status} - Progreso: {progress_text}%")

            if status in ['Done', 'Stopped', 'Interrupted']:
                if status != 'Done':
                    self.status = TaskStatus.CANCELLED
                break

            time.sleep(check_interval)

    def _create_gmp_connection(self):
        """Factoría de conexiones GMP para reutilizar en cada llamada."""
        connection = TLSConnection(
            hostname=self.hostname,
            port=self.port,
            timeout=60  # Timeout por operación individual, no por sesión
        )
        return Gmp(connection=connection, transform=EtreeTransform())
    
    def _fetch_report(self, gmp: Gmp) -> None:
        """Obtiene el reporte XML del escaneo"""
        report_response = gmp.get_report(
            report_id=self.report_id,
            report_format_id='a994b278-1f62-11e1-96ac-406186ea4fc5',  # XML
            ignore_pagination=True,
            details=True
        )
        
        from lxml import etree
        self._report_xml = etree.tostring(report_response, encoding='unicode', pretty_print=True)
        self.logger.info("Reporte XML obtenido")
    
    def _process_results(self) -> None:
        """Procesa el XML del reporte y lo convierte a estructura de datos."""
        try:
            if not self._report_xml:
                raise RuntimeError("No hay reporte XML disponible")
            
            # REEMPLAZAR: JSONManager.openvas_xml_to_json
            self.results = self._parse_openvas_report(self._report_xml)
            self.logger.info("Resultados OpenVAS procesados")
        
        except Exception as e:
            self.logger.error(f"Error procesando resultados OpenVAS: {e}", exc_info=True)
            self.results = None
            raise

    def wait(self, timeout: Optional[float] = None) -> bool:
        """
        Override: OpenVAS gestiona su propio ciclo interno.
        Solo esperamos a que _finished se active (sin timeout o con límite razonable).
        """
        try:
            # Esperamos sin límite (None) o con un máximo razonable de 8h
            safe_timeout = min(timeout, 28800) if timeout is not None else None
            finished = self._finished.wait(safe_timeout)

            if not finished:
                self.status = TaskStatus.TIMEOUT
                self.logger.error("Timeout esperando finalización de OpenVAS")
                return False

            if self.status in (TaskStatus.CANCELLED, TaskStatus.FAILED, TaskStatus.TIMEOUT):
                return False

            if self.results is None:
                self.status = TaskStatus.FAILED
                self.logger.error("OpenVAS finalizó pero no hay resultados")
                return False

            self.status = TaskStatus.COMPLETED
            self.progress = 100
            return True

        except Exception as e:
            self.status = TaskStatus.FAILED
            self.logger.error(f"Error en wait de OpenVAS: {e}", exc_info=True)
            return False

    def _parse_openvas_report(self, report_xml: str) -> Dict:
        """Parsea XML de reporte OpenVAS a estructura de datos planos."""
        from lxml import etree as lxml_etree
        from typing import List, Tuple
        
        def _classify_severity(score: float) -> str:
            if score == 0.0:
                return 'Log'
            elif score < 4.0:
                return 'Low'
            elif score < 7.0:
                return 'Medium'
            elif score < 9.0:
                return 'High'
            else:
                return 'Critical'
        
        def _extract_references(refs) -> Tuple[List[str], List[str], List[str], List[str]]:
            cve_ids, cert_refs, bugtraq_ids, other_refs = [], [], [], []
            for ref in refs:
                ref_type = ref.get('type', '').upper()
                ref_id = ref.get('id', '')
                if ref_type == 'CVE':
                    cve_ids.append(ref_id)
                elif ref_type in ['CERT-BUND', 'DFN-CERT']:
                    cert_refs.append(f"{ref_type}:{ref_id}")
                elif ref_type == 'BID':
                    bugtraq_ids.append(ref_id)
                else:
                    other_refs.append(f"{ref_type}:{ref_id}")
            return cve_ids, cert_refs, bugtraq_ids, other_refs
        
        # Parsear XML
        if isinstance(report_xml, str):
            root = lxml_etree.fromstring(report_xml.encode('utf-8'))
        elif isinstance(report_xml, bytes):
            root = lxml_etree.fromstring(report_xml)
        else:
            import xml.etree.ElementTree as ET
            xml_str = ET.tostring(report_xml, encoding='unicode')
            root = lxml_etree.fromstring(xml_str.encode('utf-8'))
        
        report = root.xpath('//report')[0]
        report_id = report.get('id')
        
        task = root.xpath('//task')[0]
        task_id = task.get('id')
        
        results = root.xpath('//report/results/result')
        
        vulnerabilities = {}
        scan_results = []
        hosts_found = set()
        
        for result in results:
            host_ip = result.xpath('host/text()')[0] if result.xpath('host/text()') else None
            if not host_ip:
                continue
            
            hosts_found.add(host_ip)
            
            nvt = result.xpath('nvt')[0] if result.xpath('nvt') else None
            if nvt is None:
                continue
            
            nvt_oid = nvt.get('oid')
            if not nvt_oid:
                continue
            
            if nvt_oid not in vulnerabilities:
                name = nvt.xpath('name/text()')[0] if nvt.xpath('name/text()') else 'Unknown'
                family = nvt.xpath('family/text()')[0] if nvt.xpath('family/text()') else None
                
                severity = result.xpath('severity/text()')[0] if result.xpath('severity/text()') else '0.0'
                severity_score = float(severity) if severity else 0.0
                
                cvss_base = nvt.xpath('cvss_base/text()')[0] if nvt.xpath('cvss_base/text()') else None
                cvss_base_score = float(cvss_base) if cvss_base else severity_score
                
                cvss_vector = None
                cvss_tags = nvt.xpath('tags/text()')
                tags_dict = {}
                
                if cvss_tags:
                    tags_text = cvss_tags[0]
                    for tag in tags_text.split('|'):
                        if '=' in tag:
                            key, value = tag.split('=', 1)
                            tags_dict[key.strip().lower()] = value.strip()
                        if 'cvss_base_vector=' in tag.lower():
                            cvss_vector = tag.split('=', 1)[1].strip()
                
                refs = nvt.xpath('refs/ref')
                cve_ids, cert_refs, bugtraq_ids, other_refs = _extract_references(refs)
                
                qod = nvt.xpath('qod')[0] if nvt.xpath('qod') else None
                qod_value = int(qod.xpath('value/text()')[0]) if qod and qod.xpath('value/text()') else None
                qod_type = qod.xpath('type/text()')[0] if qod and qod.xpath('type/text()') else None
                
                vulnerabilities[nvt_oid] = {
                    'nvt_oid': nvt_oid,
                    'name': name,
                    'severity_score': severity_score,
                    'severity_class': _classify_severity(severity_score),
                    'cvss_base_score': cvss_base_score,
                    'cvss_vector': cvss_vector,
                    'cve_ids': ','.join(cve_ids) if cve_ids else None,
                    'cert_refs': ','.join(cert_refs) if cert_refs else None,
                    'bugtraq_ids': ','.join(bugtraq_ids) if bugtraq_ids else None,
                    'other_refs': ','.join(other_refs) if other_refs else None,
                    'summary': tags_dict.get('summary', ''),
                    'description': result.xpath('description/text()')[0] if result.xpath('description/text()') else tags_dict.get('vuldetect', ''),
                    'impact': tags_dict.get('impact', ''),
                    'insight': tags_dict.get('insight', ''),
                    'affected_software': tags_dict.get('affected', ''),
                    'solution_type': tags_dict.get('solution_type', 'Mitigation'),
                    'solution': tags_dict.get('solution', ''),
                    'qod_value': qod_value,
                    'qod_type': qod_type,
                    'family': family,
                    'category': nvt.xpath('category/text()')[0] if nvt.xpath('category/text()') else None
                }
            
            scan_results.append({
                'nvt_oid': nvt_oid,
                'host_ip': host_ip,
                'port': result.xpath('port/text()')[0] if result.xpath('port/text()') else None,
                'threat': result.xpath('threat/text()')[0] if result.xpath('threat/text()') else None
            })
        
        return {
            'scan_data': {'task_id': task_id, 'report_id': report_id},
            'vulnerabilities': list(vulnerabilities.values()),
            'scan_results': scan_results,
            'hosts': list(hosts_found)
        }