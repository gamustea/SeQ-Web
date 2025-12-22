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
    PENDING = "pending"       # Esperando para iniciar
    RUNNING = "running"       # En ejecución activa
    COMPLETED = "completed"   # Completado exitosamente
    FAILED = "failed"         # Falló con error
    CANCELLED = "cancelled"   # Cancelado por usuario/sistema
    TIMEOUT = "timeout"       # Excedió tiempo límite
    
    def __str__(self):
        return self.value


class _Task(ABC):
    """
    Clase base abstracta para representar una tarea de escaneo de puertos o vulnerabilidades.
    
    Esta clase contiene la lógica común necesaria para ejecutar comandos externos de forma asíncrona,
    manejar la captura de progresos, gestionar el estado de la tarea y almacenar resultados. 
    
    Las subclases deben implementar la construcción del comando específico y el procesamiento
    de los resultados correspondientes a la herramienta usada.
    """

    def __init__(self, target: str, timeout: int = 20):
        self.timeout = timeout
        self.status = TaskStatus.PENDING  # ✅ Cambiar de NOT_STARTED a PENDING
        self.results: Optional[Any] = None
        self.target: str = target
        self.config_reader = ConfigReader()
        self.logger = SecOpsLogger(name=__name__).get_logger()
        self.progress: int = 0
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._finished = threading.Event()
        self._output_file: Optional[Path] = None

    @abstractmethod
    def _build_command(self) -> List[str]:
        """
        Método abstracto que debe implementar cada subclase para construir la lista de argumentos
        que ejecutarán el comando específico de escaneo externo.

        Returns:
            List[str]: Lista de argumentos para el comando a ejecutar.
        """
        pass

    @abstractmethod
    def _process_results(self) -> None:
        """
        Método abstracto para ser implementado por la subclase que debe procesar los resultados
        generados por la herramienta, usualmente leyendo y parseando un archivo de reporte generado.
        """
        pass

    def _parse_progress(self, line: str) -> int:
        """
        Extrae el porcentaje de progreso de una línea de la salida estándar del proceso.
        Este método es genérico, las subclases pueden sobreescribirlo si su herramienta usa otro formato.

        Args:
            line (str): Línea de texto proveniente de la salida estándar del proceso.

        Returns:
            int: Porcentaje (0-100) si se detecta, -1 si no hay porcentaje en la línea.
        """
        # Busca un número entero o decimal seguido de %
        match = re.search(r'(\d+(?:\.\d+)?)%', line)
        if match:
            prog_float = float(match.group(1))
            if 0 <= prog_float <= 100:
                return int(round(prog_float))
        return -1

    def _read_output(self):
        """
        Método que corre en un hilo separado para leer la salida estándar del proceso en ejecución,
        capturando progreso y acumulando salida para debug o análisis.
        """
        output_lines = []
        while True:
            if self._proc is None or self._proc.stdout is None:
                break
            line = self._proc.stdout.readline()
            if not line:  # EOF
                break
            self.logger.debug(f"Output: {line.strip()}")
            output_lines.append(line)
            prog = self._parse_progress(line)
            if prog != -1:
                with self._lock:
                    self.progress = prog
        
        self._finished.set()

    def scan(self) -> None:
        """Inicia el escaneo."""
        if self._proc and self._proc.poll() is None:
            self.logger.warning("El escaneo ya está en ejecución")
            return
        try:
            self.status = TaskStatus.RUNNING  # ✅ Cambiar estado
            cmd = self._build_command()
            self.logger.info(f"Iniciando escaneo con comando: {' '.join(cmd)}")

            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            self._thread = threading.Thread(target=self._read_output, daemon=True)
            self._thread.start()
            self._thread.join()

            self.progress = 100
            self.status = TaskStatus.COMPLETED  # ✅ Cambiar estado
            self.logger.info("Escaneo finalizado.")

        except Exception as e:
            self.status = TaskStatus.FAILED  # ✅ Cambiar estado
            self.logger.error(f"Error iniciando escaneo: {e}")
    
    def wait(self, timeout: Optional[float] = None) -> bool:
        """Espera a que termine el escaneo."""
        finished = self._finished.wait(timeout)
        if finished:
            try:
                if self._proc:
                    retcode = self._proc.poll()
                    if retcode != 0:
                        self.status = TaskStatus.FAILED  # ✅ Cambiar estado
                        self.logger.error(f"El escaneo terminó con error: código {retcode}")
                        return False

                self._process_results()
                self.status = TaskStatus.COMPLETED  # ✅ Cambiar estado
                self.logger.info("Escaneo completado correctamente.")
            except Exception as e:
                self.status = TaskStatus.FAILED 
                self.logger.error(f"Error procesando resultados: {e}")
                return False
        else:
            self.status = TaskStatus.TIMEOUT
            self.logger.error("Timeout agotado esperando al escaneo")

        return finished

    def is_finished(self) -> bool:
        """
        Indica si la tarea ha finalizado la lectura de la salida.

        Returns:
            bool: True si terminó, False si sigue en curso.
        """
        return self._finished.is_set()

    def cancel(self) -> None:
        """Cancela el escaneo."""
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            self.status = TaskStatus.CANCELLED  # ✅ Ya estaba bien
            self._finished.set()
            self.logger.info("Escaneo cancelado por el usuario")

    def get_status_string(self) -> str:
        """Obtiene el estado como string para guardar en BD."""
        return self.status.value


class NmapScanTask(_Task):
    """
    Implementación concreta de _Task para ejecutar escaneos Nmap.

    Ejecuta nmap con parámetros configurables, captura salida XML y la procesa
    con la librería python-nmap para obtener información estructurada.
    """

    def __init__(self, target_host="127.0.0.1", target_ports="1-6000", timeout: int = 20):
        super().__init__(target_host, timeout)
        TEMP_DIR = ConfigReader().get_directory_of(DirectoryType.TEMP)
        FILE_NAME = f"nmap_scan_{self.target}_{int(time.time())}.xml" 
        self.target_ports = target_ports
        self._output_file = Path(f"{TEMP_DIR}/{FILE_NAME}")
        self.scanner = None  # Instancia python-nmap para análisis XML

    def _build_command(self) -> List[str]:
        """
        Construye el comando nmap con los argumentos necesarios
        para realizar un escaneo TCP completo en los puertos indicados,
        y generar un reporte XML para posterior análisis.

        Returns:
            List[str]: Lista con los argumentos para llamar a nmap.
        """
        return [
            "nmap",
            "-sT",
            "-p", self.target_ports,
            "-oX", str(self._output_file),
            self.target,
            "--stats-every", "1s"
        ]

    def _process_results(self) -> None:
        """
        Tras finalizar el escaneo, lee el archivo XML generado y lo analiza con python-nmap,
        almacenando la información estructurada en `self.results`.
        """

        self.scanner = PortScanner()
        if self._output_file.exists(): # type: ignore
            with self._output_file.open("r") as f: # type: ignore
                xml_data = f.read()
            self.results = self.scanner.analyse_nmap_xml_scan(xml_data)
        else:
            self.logger.error("No se generó archivo XML de salida.")
            self.results = None


class NiktoScanTask(_Task):
    """
    Implementación concreta de _Task para ejecutar escaneos de vulnerabilidades web con Nikto.

    Ejecuta Nikto usando subprocess en segundo plano, genera un reporte XML y luego
    lo procesa para obtener resultados en formato JSON.
    """

    def __init__(self, target_domain="http://testphp.vulnweb.com", timeout: int = 20):
        super().__init__(target_domain, timeout)
        self.temp_path = DirectoryChecker().verify_directory(DirectoryType.TEMP) / "nikto_scan.xml"
        self._output_file = self.temp_path

    def _build_command(self) -> List[str]:
        """
        Construye el comando para ejecutar Nikto, generando reporte XML sin interacción,
        con tiempo máximo configurable.

        Returns:
            List[str]: Lista con los argumentos para llamar a Nikto.
        """
        return [
            "nikto",
            "-h", self.target,
            "-o", str(self.temp_path),
            "-Format", "xml",
            "-nointeractive",
            "-maxtime", str(self.timeout),
        ]

    def _parse_progress(self, line: str) -> int:
        """
        Nikto no ofrece progreso en la salida, por lo que esta implementación
        simplemente devuelve -1 indicando falta de información.

        Args:
            line (str): Línea de salida de Nikto.

        Returns:
            int: Siempre -1 porque no se puede determinar progreso.
        """
        return -1

    def _process_results(self) -> None:
        """
        Procesa el reporte XML generado por Nikto usando la clase `JSONManager`
        para convertirlos a formato JSON, y guarda el resultado en `self.results`.
        """
        try:
            self.results = JSONManager.convert_multi_niktoscan_xml_to_json(str(self.temp_path))
        except Exception as e:
            self.logger.error(f"No se pudo leer/parsear el fichero XML de Nikto: {e}")
            self.results = None
            raise
