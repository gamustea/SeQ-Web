"""
Script de prueba para ProgramedScanManager.register().

Ejecuta el metodo register con argumentos validos para los tres tipos de
escaneo y verifica que cada fila queda correctamente insertada en la BD.

Uso:
    cd API && python prueba.py
"""

from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.unit_of_work import initialize
from src.modules.sentinel.managers import ProgramedScanManager
from src.modules.sentinel.repositories import ProgramedScanRepository
from src.modules.sentinel.model import ScanType


def probar_register(
    user_id: int,
    scan_type: ScanType,
    arguments: dict[str, str],
    schedule_type: str,
    schedule_config: dict,
) -> None:
    print(f"\n--- Registrando {scan_type.value} para user_id={user_id} ---")
    print(f"  arguments:       {arguments}")
    print(f"  schedule_type:   {schedule_type}")
    print(f"  schedule_config: {schedule_config}")

    ProgramedScanManager.register(
        user_id=user_id,
        scan_type=scan_type,
        arguments=arguments,
        schedule_type=schedule_type,
        schedule_config=schedule_config,
    )
    print("  [+] register() ejecutado sin errores.")

    with UnitOfWork() as uow:
        repo = ProgramedScanRepository(uow)
        scans = repo.get_by_user_and_type(user_id, scan_type)
        if scans:
            ps = scans[-1]
            print(f"  [+] Verificado en BD: id={ps.id}, "
                  f"scan_type={ps.scan_type}, "
                  f"is_active={ps.is_active}, "
                  f"arguments={ps.arguments}")


def main() -> None:
    print("Inicializando conexion a la base de datos...")
    initialize()

    user_id = 1

    probar_register(
        user_id=user_id,
        scan_type=ScanType.NMAP,
        arguments={"target_host": "192.168.1.1", "target_ports": "1-1000"},
        schedule_type="interval",
        schedule_config={"every": 60, "unit": "minutes"},
    )

    probar_register(
        user_id=user_id,
        scan_type=ScanType.NIKTO,
        arguments={"target_domain": "example.com"},
        schedule_type="interval",
        schedule_config={"every": 120, "unit": "minutes"},
    )

    probar_register(
        user_id=user_id,
        scan_type=ScanType.OPENVAS,
        arguments={"target": "10.0.0.5"},
        schedule_type="cron",
        schedule_config={"cron": "0 2 * * *"},
    )

    print("\nTodas las pruebas completadas.")


if __name__ == "__main__":
    main()
