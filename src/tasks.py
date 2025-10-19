
import nmap
import subprocess
import json

from pathlib import Path
from abc import ABC, abstractmethod
from typing import Dict, Any



class _Task(ABC):
    """
    Clase base abstracta para tareas de escaneo de puertos.
    Proporciona una interfaz común para diferentes tipos de tareas de escaneo.
    Attributes:
    -----------------------------------------------------------------------------------------
        progress (int): El progreso actual de la tarea de escaneo
        results (dict): Los resultados del escaneo de puertos
    """

    def __init__(self, target):
        self.progress = 0
        self.results: Any = None
        self.target: str = target


    @abstractmethod
    def scan(self):
        pass


    def get_task_results(self) -> Any | None:
        """Obtiene los resultados del escaneo de puertos.
        Returns:
            Any: Los resultados del escaneo de puertos si están disponibles, de lo contrario None.
        """
        return self.results


class NmapScanTask(_Task):
    """
    Escáner de puertos que usa la biblioteca nmap para escanear puertos en un objetivo dado.
    Proporciona métodos para iniciar un escaneo y obtener los resultados del escaneo.
    Attributes:
    -----------------------------------------------------------------------------------------
        target (str): La dirección IP o el nombre de host del objetivo a escanear
    """

    def __init__(self, target_host: str="127.0.0.1", target_ports: str="1-1024"):
        """
        Inicializa el escáner de puertos nmap con el objetivo y los puertos
        Args:
            target_host (str): La dirección IP o el nombre de host del objetivo a escanear
            target_ports (str): Los puertos a escanear en el objetivo
        """
        super().__init__(target_host)

        self.target_ports = target_ports
        self.scanner = nmap.PortScanner()


    def scan(self) -> None:
        """Inicia el escaneo de puertos en el objetivo especificado.
        Utiliza la biblioteca nmap para escanear los puertos especificados en el objetivo.
        Los resultados del escaneo se almacenan en el atributo 'results'.
        """
        self.results = self.scanner.scan(
            self.target,
            self.target_ports
        )


class NiktoScanTask(_Task):
    """
    Escáner de vulnerabilidades web que usa la herramienta Nikto para escanear un objetivo web.
    Proporciona métodos para iniciar un escaneo y obtener los resultados del escaneo.
    Attributes:
    -----------------------------------------------------------------------------------------
        target (str): La URL del objetivo web a escanear
    """


    def __init__(self, target_domain: str="http://localhost"):
        """
        Inicializa el escáner de vulnerabilidades web Nikto con el objetivo web.
        Args:
            target_host (str): La URL del objetivo web a escanear
        """
        super().__init__(target_domain)
        self.out_path = "temp/nikto_output.json"


    def scan(self) -> None:
        """
        Ejecuta nikto contra `target` y guarda salida en JSON en out_path.
        Devuelve dict con el JSON (o None si error).
        """
        out_file = Path(self.out_path).resolve()
        cmd = ["nikto", "-h", self.target, "-o", str(out_file), "-Format", "json", "-nointeractive"]

        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            print("nikto falló:", proc.returncode)
            print("stderr:", proc.stderr)
            return

        # leer JSON generado (Nikto crea el fichero -Format json)
        try:
            with open(out_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.results = data
        except Exception as e:
            print("No se pudo leer/parsear el fichero de salida:", e)