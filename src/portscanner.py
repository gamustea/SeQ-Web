
import nmap

class SelfPortScanner:
    """
    Escáner de puertos que usa la biblioteca nmap para escanear puertos en un objetivo dado.
    Proporciona métodos para iniciar un escaneo y obtener los resultados del escaneo.
    Attributes:
    -----------------------------------------------------------------------------------------
        target (str): La dirección IP o el nombre de host del objetivo a escanear
    """


    def __init__(self, target):
        self.target = target
        self.scanner = nmap.PortScanner()

    def wide_scan(self):
        return self.scan("1-65535")

    def scan(self, ports="1-1024"):
        self.scanner.scan(self.target, ports)
        return self.scanner[self.target]['tcp'].keys()

    def get_scan_results(self):
        results = {}
        for proto in self.scanner[self.target].all_protocols():
            results[proto] = []
            lport = self.scanner[self.target][proto].keys()
            for port in lport:
                results[proto].append({
                    'port': port,
                    'state': self.scanner[self.target][proto][port]['state'],
                    'name': self.scanner[self.target][proto][port]['name']
                })
        return results