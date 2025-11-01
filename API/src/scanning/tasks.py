import subprocess
import threading
import re
import time
from pathlib import Path
from typing import Optional, Any, List
from enum import Enum, auto
from abc import ABC, abstractmethod

from src.misc.configread import ConfigReader
from src.misc.logging import SecOpsLogger
from src.misc.conversion import JSONManager
from src.misc.directorychecker import DirectoryChecker


class TaskStatus(Enum):
    """
    Enum que representa los diferentes estados en los que puede estar una tarea de escaneo.
    Se usa para controlar el ciclo de vida y el progreso del escaneo de forma consistente.
    """
    NOT_STARTED = auto()     # La tarea todavía no ha empezado su ejecución.
    RUNNING = auto()         # La tarea está actualmente en ejecución.
    COMPLETED = auto()       # La tarea terminó exitosamente.
    FAILED = auto()          # La tarea terminó con un error.
    CANCELLED = auto()       # La tarea fue cancelada por el usuario o el sistema.


class _Task(ABC):
    """
    Clase base abstracta para representar una tarea de escaneo de puertos o vulnerabilidades.
    
    Esta clase contiene la lógica común necesaria para ejecutar comandos externos de forma asíncrona,
    manejar la captura de progresos, gestionar el estado de la tarea y almacenar resultados. 
    
    Las subclases deben implementar la construcción del comando específico y el procesamiento
    de los resultados correspondientes a la herramienta usada.
    """

    def __init__(self, target: str):
        """
        Inicializa la tarea de escaneo con el objetivo (host o dominio) a escanear.

        Args:
            target (str): Dirección IP, rango o dominio a escanear.
        """
        self.status = TaskStatus.NOT_STARTED  # Estado inicial: no iniciado
        self.results: Optional[Any] = None   # Resultados estructurados tras finalización
        self.target: str = target             # Objetivo del escaneo
        self.config_reader = ConfigReader()  # Para leer configuraciones externas
        self.logger = SecOpsLogger(name=__name__).get_logger()  # Logger para eventos e info
        self.progress: int = 0                # Progreso del escaneo (0-100%)
        self._proc: Optional[subprocess.Popen] = None  # Proceso externo que ejecuta el escaneo
        self._thread: Optional[threading.Thread] = None  # Hilo para lectura de salida del proceso
        self._lock = threading.Lock()         # Lock para sincronización de progreso
        self._finished = threading.Event()    # Evento que indica finalización de lectura de salida
        self._output_file: Optional[Path] = None  # Archivo donde se guardan resultados (XML, etc)

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
        # Indica que ya terminó la lectura completa
        self._finished.set()

    def scan(self) -> None:
        """
        Método principal para iniciar el escaneo.

        - Construye el comando externo desde la subclase.
        - Inicia el proceso externo capturando la salida.
        - Inicia un hilo que lee el stdout para monitorear progreso.
        - Cambia el estado a RUNNING.
        - La ejecución es bloqueante hasta que el proceso y el hilo terminan.
        """
        if self._proc and self._proc.poll() is None:
            self.logger.warning("El escaneo ya está en ejecución")
            return
        try:
            self.status = TaskStatus.RUNNING
            cmd = self._build_command()
            self.logger.info(f"Iniciando escaneo con comando: {' '.join(cmd)}")

            # Ejecuta el proceso externo subshell
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            # Lanza hilo para leer la salida sin bloqueo
            self._thread = threading.Thread(target=self._read_output, daemon=True)
            self._thread.start()

            # Espera a que termine el hilo de lectura (y con ello el proceso)
            self._thread.join()

            self.progress = 100
            self.status = TaskStatus.COMPLETED
            self.logger.info("Escaneo finalizado.")

        except Exception as e:
            self.status = TaskStatus.FAILED
            self.logger.error(f"Error iniciando escaneo: {e}")

    def is_finished(self) -> bool:
        """
        Indica si la tarea ha finalizado la lectura de la salida.

        Returns:
            bool: True si terminó, False si sigue en curso.
        """
        return self._finished.is_set()

    def wait(self, timeout: Optional[float] = None) -> bool:
        """
        Método para bloquear hasta que el escaneo termine o expire timeout.
        Posteriormente procesa los resultados.

        Args:
            timeout (Optional[float]): Tiempo máximo a esperar (segundos).

        Returns:
            bool: True si terminó dentro del timeout, False si no.
        """
        finished = self._finished.wait(timeout)
        if finished:
            try:
                if self._proc:
                    retcode = self._proc.poll()
                    if retcode != 0:
                        self.status = TaskStatus.FAILED
                        self.logger.error(f"El escaneo terminó con error: código {retcode}")
                        return False

                # Procesar resultados con implementación específica
                self._process_results()
                self.status = TaskStatus.COMPLETED
                self.logger.info("Escaneo completado correctamente.")
            except Exception as e:
                self.status = TaskStatus.FAILED
                self.logger.error(f"Error procesando resultados: {e}")
                return False
        else:
            self.status = TaskStatus.FAILED
            self.logger.error("Timeout agotado esperando al escaneo")

        return finished

    def cancel(self) -> None:
        """
        Cancela el escaneo si está en ejecución, terminando el proceso externo
        y marcando la tarea como cancelada.
        """
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            self.status = TaskStatus.CANCELLED
            self._finished.set()
            self.logger.info("Escaneo cancelado por el usuario")

    def get_task_results(self) -> Optional[Any]:
        """
        Devuelve los resultados obtenidos tras la finalización del escaneo.

        Returns:
            Optional[Any]: Resultados del escaneo en formato estructurado o None si no disponible.
        """
        return self.results


class NmapScanTask(_Task):
    """
    Implementación concreta de _Task para ejecutar escaneos Nmap.

    Ejecuta nmap con parámetros configurables, captura salida XML y la procesa
    con la librería python-nmap para obtener información estructurada.
    """

    def __init__(self, target_host="127.0.0.1", target_ports="1-6000"):
        super().__init__(target_host)
        TEMP_DIR = ConfigReader().get_directory_of("tempdir")
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
        from nmap import PortScanner
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

    def __init__(self, target_domain="http://testphp.vulnweb.com"):
        super().__init__(target_domain)
        self.temp_path = DirectoryChecker().verify_directory("tempdir") / "nikto_scan.xml"
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
            "-maxtime", "20",
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
