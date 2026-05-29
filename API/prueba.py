"""
Script de prueba: inserta escaneos programados con distintos intervalos.

Una vez insertados, deja correr la aplicacion normalmente (python run.py)
y el scheduler integrado los ejecutara automaticamente en cada ciclo.

Uso:
    cd API && python prueba.py
"""

from src.modules.infrastructure.unit_of_work import initialize
from src.modules.sentinel.managers import ProgramedScanManager
from src.modules.sentinel.model import ScanType


def main() -> None:
    print("Inicializando conexion a la base de datos...")
    initialize()

    user_id = 1

    print("\n[1] Nmap 192.168.1.1:1-1024 cada 1 minuto ...")
    ProgramedScanManager.register(
        user_id=user_id,
        scan_type=ScanType.NMAP,
        arguments={"target_host": "192.168.1.1", "target_ports": "1-1024"},
        schedule_type="interval",
        schedule_config={"every": 1, "unit": "minutes"},
    )

    print("[2] Nmap 192.168.1.1:1-65000 cada 10 minutos ...")
    ProgramedScanManager.register(
        user_id=user_id,
        scan_type=ScanType.NMAP,
        arguments={"target_host": "192.168.1.1", "target_ports": "1-65000"},
        schedule_type="interval",
        schedule_config={"every": 10, "unit": "minutes"},
    )

    print("[3] Nikto http://localhost:8080 cada 5 minutos ...")
    ProgramedScanManager.register(
        user_id=user_id,
        scan_type=ScanType.NIKTO,
        arguments={"target_domain": "http://localhost:8080"},
        schedule_type="interval",
        schedule_config={"every": 5, "unit": "minutes"},
    )

    print("[4] Nikto https://emesa.com cada 30 minutos ...")
    ProgramedScanManager.register(
        user_id=user_id,
        scan_type=ScanType.NIKTO,
        arguments={"target_domain": "https://emesa.com"},
        schedule_type="interval",
        schedule_config={"every": 30, "unit": "minutes"},
    )

    print("\n[+] Escaneos persistidos. Arranca con: python run.py")


if __name__ == "__main__":
    main()
