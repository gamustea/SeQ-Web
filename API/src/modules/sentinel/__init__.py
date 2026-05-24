"""
src.modules.sentinel - Módulo de escaneos de seguridad

Exponente:
    - NmapScanManager: Escaneo de puertos
    - NiktoScanManager: Escaneo web
    - OpenVASScanManager: Escaneo de vulnerabilidades
    - Modelos: Scan, Host, Port, etc.
    - Endpoints: sentinel_bp
"""

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

from .endpoints import sentinel_bp

__all__ = [
    # Models
    "Host",
    "NiktoIncident",
    "NiktoScan",
    "NmapScan",
    "OpenPort",
    "OpenVASScan",
    "OpenVASScanResult",
    "OpenVASVulnerability",
    "Port",
    "ProgramedScan",
    "Scan",
    "ScanIncident",
    "ScanStatus",
    "SentinelDocument",
    "TargetPort",
    # Managers
    "NmapScanManager",
    "NiktoScanManager",
    "OpenVASScanManager",
    "ProgramedScanManager",
    "ScanManager",
    # Repositories
    "ProgramedScanRepository",
    "ScanRepository",
    "SentinelReportRepository",
    # Endpoints
    "sentinel_bp",
    # Reports
    "PDFCreator",
    "NmapPrintingStrategy",
    "NiktoPrintingStrategy",
    "OpenVASPrintingStrategy",
    # Scheduling
    "Scheduler",
]