import subprocess
import threading
import re
import time
from pathlib import Path
from typing import Optional, Any, List, Dict
from enum import Enum, auto
from abc import ABC, abstractmethod
from nmap import PortScanner

from src.misc.configread import ConfigReader, DirectoryType
from src.misc.logging import SecOpsLogger
from src.misc.conversion import JSONManager
from src.misc.directorychecker import DirectoryChecker


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

    def __init__(self, target: str, timeout: int = 20):
        self.timeout = timeout
        self.status = TaskStatus.PENDING
        self.results: Optional[Any] = None
        self.target: str = target
        self.config_reader = ConfigReader()
        self.logger = SecOpsLogger(name=__name__).get_logger()
        self.progress: int = 0
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._finished = threading.Event()
        self._started = threading.Event()
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
        """
        Inicia el escaneo de forma ASÍNCRONA.
        NO bloquea - retorna inmediatamente después de iniciar.
        """
        if self._proc and self._proc.poll() is None:
            self.logger.warning("El escaneo ya está en ejecución")
            return
        
        try:
            self.status = TaskStatus.RUNNING
            cmd = self._build_command()
            self.logger.info(f"Iniciando escaneo con comando: {' '.join(cmd)}")
            
            # Asegurar que el directorio de salida existe
            if self._output_file and not self._output_file.parent.exists():
                self._output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Iniciar proceso
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Verificar que el proceso inició
            time.sleep(0.1)
            if self._proc.poll() is not None:
                self.status = TaskStatus.FAILED
                raise RuntimeError(f"Proceso falló al iniciar (código {self._proc.returncode})")
            
            # Iniciar thread de lectura (NO bloqueante)
            self._thread = threading.Thread(target=self._read_output, daemon=True)
            self._thread.start()
            
            # Esperar solo a que el thread INICIE (no a que termine)
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
            
            # Verificar código de retorno
            if self._proc and self._proc.returncode != 0:
                self.status = TaskStatus.FAILED
                self.logger.error(f"Proceso terminó con error: código {self._proc.returncode}")
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
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            time.sleep(0.5)
            if self._proc.poll() is None:
                self._proc.kill()
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
            "nmap",
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

    def __init__(self, target_domain="http://testphp.vulnweb.com", timeout: int = 20):
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

    def _parse_progress(self, line: str) -> int:
        """Nikto no ofrece progreso."""
        return -1

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