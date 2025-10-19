
import nmap

from abc import ABC, abstractmethod
from typing import Dict, Any



class Task(ABC):
    """
    Clase base abstracta para tareas de escaneo de puertos.
    Proporciona una interfaz común para diferentes tipos de tareas de escaneo.
    Attributes:
    -----------------------------------------------------------------------------------------
        progress (int): El progreso actual de la tarea de escaneo
        results (dict): Los resultados del escaneo de puertos
    """

    def __init__(self, target_host: str="localhost"):
        self.progress = 0
        self.results: Any = None
        self.target_host: str = target_host


    @abstractmethod
    def scan(self):
        pass


    def get_task_results(self) -> Any | None:
        """Obtiene los resultados del escaneo de puertos.
        Returns:
            Any: Los resultados del escaneo de puertos si están disponibles, de lo contrario None.
        """
        return self.results


class NmapScanTask(Task):
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
            self.target_host, 
            self.target_ports
        )