import nmap
import subprocess
from pathlib import Path
from abc import ABC, abstractmethod
from typing import Any, Optional

from misc.conversion import JSONManager


class _Task(ABC):
    """
    Clase base abstracta para tareas de escaneo de puertos.
    """

    def __init__(self, target: str):
        self.progress: int = 0
        self.results: Optional[Any] = None
        self.target: str = target

    @abstractmethod
    def scan(self) -> None:
        pass

    def get_task_results(self) -> Optional[Any]:
        """
        Obtiene los resultados del escaneo.
        """
        return self.results


class NmapScanTask(_Task):
    """
    Escáner usando la librería nmap para escanear puertos.
    Escaneo rápido y detallado con límite de tiempo para obtener una cantidad significativa de datos sin tardar demasiado.
    """

    def __init__(self, target_host: str = "127.0.0.1", target_ports: str = "1-6000", timeout: int = 10):
        super().__init__(target_host)
        self.target_ports = target_ports
        self.timeout = timeout
        self.scanner = nmap.PortScanner()

    def scan(self) -> None:
        try:
            self.results = self.scanner.scan(
                self.target,
                self.target_ports,
                arguments=f'--host-timeout {self.timeout}s'
            )
        except nmap.PortScannerError as e:
            print(f"Error Nmap: {e}")
        except Exception as e:
            print(f"Error inesperado Nmap: {e}")


class NiktoScanTask(_Task):
    """
    Escáner de vulnerabilidades web usando Nikto.
    """

    def __init__(self, target_domain: str = "http://testphp.vulnweb.com"):
        super().__init__(target_domain)
        self.out_dir = Path("temp").resolve()
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.out_path = self.out_dir / "nikto_output.xml"

    def scan(self) -> None:
        """Ejecuta Nikto y procesa los resultados en formato XML."""
        cmd = [
            "nikto",
            "-h",
            self.target,
            "-o",
            str(self.out_path),
            "-Format",
            "xml",
            "-nointeractive",
            "-maxtime",
            "20",
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"Nikto falló: {proc.returncode}")
            print(f"stderr: {proc.stderr}")
            return

        try:
            self.results = JSONManager.convert_multi_niktoscan_xml_to_json(
                str(self.out_path)
            )

        except Exception as e:
            print(f"No se pudo leer/parsear el fichero XML de Nikto: {e}")
