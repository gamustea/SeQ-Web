"""
src.modules.sentinel - Módulo de escaneos de seguridad

Exponente:
    - NmapScanManager: Escaneo de puertos
    - NiktoScanManager: Escaneo web
    - OpenVASScanManager: Escaneo de vulnerabilidades
    - Modelos: Scan, Host, Port, etc.
    - Endpoints: sentinel_bp
"""

from src.modules.system.taskqueue import QueueRegistry

from .model import (
    Host,
    NiktoIncident,
    NiktoScan,
    NmapScan,
    OpenPort,
    OpenVASScan,
    OpenVASScanResult,
    OpenVASVulnerability,
    Port,
    ProgramedScan,
    Scan,
    ScanFolder,
    ScanIncident,
    ScanStatus,
    SentinelDocument,
    TargetPort,
)

from .managers import (
    NmapScanManager,
    NiktoScanManager,
    OpenVASScanManager,
    ProgramedScanManager,
    ScanManager,
    ScanFolderManager,
)

from .repositories import (
    ProgramedScanRepository,
    ScanRepository,
    SentinelReportRepository,
)

from .services import (
    NmapPrintingStrategy,
    NiktoPrintingStrategy,
    OpenVASPrintingStrategy,
    PDFCreator,
    Scheduler,
)

from .endpoints import sentinel_blp

# Registro de las categorías de cola de este módulo (OCP).
QueueRegistry.register("sentinel.scan", "sentinel.report")

__all__ = [
    "Host", "NiktoIncident", "NiktoScan", "NmapScan", "OpenPort",
    "OpenVASScan", "OpenVASScanResult", "OpenVASVulnerability", "Port",
    "ProgramedScan", "Scan", "ScanFolder", "ScanIncident", "ScanStatus",
    "SentinelDocument", "TargetPort",
    "NmapScanManager", "NiktoScanManager", "OpenVASScanManager",
    "ProgramedScanManager", "ScanManager", "ScanFolderManager",
    "ProgramedScanRepository", "ScanRepository", "ScanFolderRepository",
    "SentinelReportRepository",
    "sentinel_blp",
    "PDFCreator", "NmapPrintingStrategy", "NiktoPrintingStrategy",
    "OpenVASPrintingStrategy",
    "Scheduler",
]