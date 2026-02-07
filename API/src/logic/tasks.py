import subprocess
import threading
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Any, List, Dict
from enum import Enum, auto
from abc import ABC, abstractmethod
from nmap import PortScanner

from src.misc.configread import ConfigReader, DirectoryType
from src.misc.logging import SecOpsLogger
from src.misc.conversion import JSONManager
from src.misc.directorychecker import DirectoryChecker

import xml.etree.ElementTree as ET
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform


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

    def __init__(self, target: str, timeout: int = 20):
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
            # Señalizar que el thread inició
            self._started.set()
            
            output_lines = []
            while True:
                if self._proc is None or self._proc.stdout is None:
                    break
                    
                line = self._proc.stdout.readline()
                if not line:  # EOF
                    break
                    
                self.logger.debug(f"Output: {line.strip()}")
                output_lines.append(line)
                
                # Actualizar progreso si está disponible
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

            # Si alguien (cancel(), OpenVASTask, etc.) ya fijó un estado final,
            # NO lo toquemos.
            if self.status in (TaskStatus.CANCELLED,
                            TaskStatus.TIMEOUT,
                            TaskStatus.FAILED):
                self.logger.info(f"wait() termina con estado {self.status.value}")
                return self.status == TaskStatus.COMPLETED

            # ---------------------------
            # A partir de aquí, solo tareas basadas en proceso que siguen RUNNING
            # ---------------------------
            if self._proc:
                if self._proc.returncode != 0:
                    self.status = TaskStatus.FAILED
                    self.logger.error(
                        f"Proceso terminó con error: código {self._proc.returncode}"
                    )
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

    def __init__(self, target_host="127.0.0.1", target_ports="1-6000", timeout: int = 20):
        super().__init__(target_host, timeout)
        TEMP_DIR = ConfigReader().get_directory_of(DirectoryType.TEMP)
        
        # Nombre único y seguro
        timestamp = int(time.time() * 1000)
        safe_target = target_host.replace("/", "_").replace(":", "_")
        FILE_NAME = f"nmap_scan_{safe_target}_{timestamp}.xml"
        
        self.target_ports = target_ports
        self._output_file = Path(f"{TEMP_DIR}/{FILE_NAME}")
        self.scanner = None
        
        # Asegurar directorio
        self._output_file.parent.mkdir(parents=True, exist_ok=True)

    def _build_command(self) -> List[str]:
        """Construye el comando nmap."""
        return [
            "sudo",
            "-n",
            "nmap",
            "-sV",
            "-sT",
            "-p", self.target_ports,
            "-oX", str(self._output_file),
            self.target,
            "--stats-every", "1s"
        ]

    def _process_results(self) -> None:
        """Procesa el XML generado por nmap."""
        try:
            self.scanner = PortScanner()
            
            if not self._output_file.exists(): # type: ignore
                self.logger.error(f"Archivo XML no existe: {self._output_file}")
                self.results = None
                return
            
            if self._output_file.stat().st_size == 0: # type: ignore
                self.logger.error(f"Archivo XML está vacío: {self._output_file}")
                self.results = None
                return
            
            with self._output_file.open("r") as f: # type: ignore
                xml_data = f.read()
            
            if not xml_data.strip():
                self.logger.error("Contenido del XML está vacío")
                self.results = None
                return
            
            
            self.results = self.scanner.analyse_nmap_xml_scan(xml_data)
            self.logger.info(f"Resultados procesados: {self._output_file}") 
        
        except Exception as e:
            self.logger.error(f"Error procesando resultados: {e}", exc_info=True)
            self.results = None
            raise


class NiktoScanTask(_Task):
    """
    Implementación concreta para escaneos Nikto.
    """

    def __init__(self, target_domain, timeout: int = 120):
        super().__init__(target_domain, timeout)
        
        # Nombre único
        timestamp = int(time.time() * 1000)
        self.temp_path = DirectoryChecker().verify_directory(DirectoryType.TEMP) / f"nikto_scan_{timestamp}.xml"
        self._output_file = self.temp_path

    def _build_command(self) -> List[str]:
        """Construye el comando Nikto."""
        return [
            "nikto",
            "-h", self.target,
            "-o", str(self.temp_path),
            "-Format", "xml",
            "-nointeractive",
            "-maxtime", str(self.timeout),
        ]

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
            
            self.results = JSONManager.convert_multi_niktoscan_xml_to_json(str(self.temp_path))
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
        timeout: int = 300
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
        """Ejecuta el escaneo completo de OpenVAS"""
        try:
            connection = TLSConnection(hostname=self.hostname, port=self.port)
            with Gmp(connection=connection, transform=EtreeTransform()) as gmp:
                gmp.authenticate(self.username, self.password)

                # Crear/obtener target
                target_id = self._get_or_create_target(gmp)

                # Obtener scanner
                scanner_id = self._get_default_scanner(gmp)

                # Crear y ejecutar tarea
                self._create_and_start_task(gmp, target_id, scanner_id)

                # Esperar finalización o cancelación
                self._wait_for_completion(gmp)

                # Si está cancelado, no intentamos obtener reporte
                if self.status == TaskStatus.CANCELLED:
                    self.logger.info("Escaneo OpenVAS cancelado; no se obtiene reporte")
                    self._finished.set()
                    return

                # Obtener reporte
                self._fetch_report(gmp)

            self._finished.set()

        except Exception as e:
            self.status = TaskStatus.FAILED
            self.logger.error(f"Error en escaneo OpenVAS: {e}", exc_info=True)
            self._finished.set()
    
    def _get_or_create_target(self, gmp: Gmp) -> str:
        """Crea o reutiliza un target en OpenVAS"""
        target_name = f"Target_{self.target}"
        
        # Buscar target existente
        targets = gmp.get_targets(filter_string=f'name="{target_name}"')
        target_list = targets.xpath('target')
        
        if target_list:
            target_id = target_list[0].attrib.get('id')
            self.logger.info(f"Reutilizando target: {target_id}")
            return target_id
        
        # Crear nuevo target
        target_response = gmp.create_target(
            name=target_name,
            hosts=[self.target],
            port_list_id=self.port_list_id,
            comment=f"Target para {self.target}"
        )
        
        target_id = target_response.attrib.get('id') or target_response.get('id')
        self.logger.info(f"Target creado: {target_id}")
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
        """Crea la tarea de escaneo y la inicia"""
        task_name = f"Scan_{self.target}_{int(time.time())}"
        
        task_response = gmp.create_task(
            name=task_name,
            config_id=self.scan_config,
            target_id=target_id,
            scanner_id=scanner_id,
            comment=f"Escaneo de {self.target}"
        )
        
        self.task_id = task_response.attrib.get('id') or task_response.get('id')
        self.logger.info(f"Tarea creada: {self.task_id}")
        
        # Iniciar escaneo
        start_response = gmp.start_task(self.task_id)
        self.report_id = start_response.xpath('report_id')[0].text
        self.logger.info(f"Escaneo iniciado. Report ID: {self.report_id}")
    
    def _wait_for_completion(self, gmp: Gmp, check_interval: int = 10) -> None:
        """Espera a que el escaneo complete"""
        while True:
            # ¿Se ha solicitado cancelación desde fuera?
            if self._cancel_event.is_set():
                self.logger.info("Cancelación solicitada para tarea OpenVAS")
                if self.task_id:
                    try:
                        gmp.stop_task(self.task_id)
                        self.logger.info(f"Tarea OpenVAS detenida: {self.task_id}")
                    except Exception as e:
                        self.logger.error(
                            f"Error al detener tarea OpenVAS {self.task_id}: {e}",
                            exc_info=True
                        )
                self.status = TaskStatus.CANCELLED
                break

            task = gmp.get_task(self.task_id)
            status = task.xpath('task/status')[0].text
            progress = task.xpath('task/progress')[0].text

            # Actualizar progreso
            with self._lock:
                self.progress = int(float(progress))

            self.logger.info(f"Estado: {status} - Progreso: {progress}%")

            if status in ['Done', 'Stopped', 'Interrupted']:
                # 'Stopped' / 'Interrupted' vienen normalmente de un stop remoto
                if status == 'Done':
                    self.logger.info(f"Escaneo finalizado correctamente: {status}")
                    # Dejamos que wait() procese resultados y marque COMPLETED
                else:
                    self.logger.info(f"Escaneo OpenVAS detenido: {status}")
                    self.status = TaskStatus.CANCELLED
                break

        time.sleep(check_interval)
    
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
        """Procesa el XML del reporte y lo convierte a JSON"""
        try:
            if not self._report_xml:
                raise RuntimeError("No hay reporte XML disponible")
            
            self.results = JSONManager.openvas_xml_to_json(self._report_xml)
            self.logger.info("Resultados OpenVAS procesados")
        
        except Exception as e:
            self.logger.error(f"Error procesando resultados OpenVAS: {e}", exc_info=True)
            self.results = None
            raise