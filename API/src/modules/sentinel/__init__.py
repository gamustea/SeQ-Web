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
    ScanManager,
)

from .repositories import (
    ScanRepository,
    SentinelReportRepository,
)

from .services import (
    NmapPrintingStrategy,
    NiktoPrintingStrategy,
    OpenVASPrintingStrategy,
    PDFCreator
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
    "Scan",
    "ScanIncident",
    "ScanStatus",
    "SentinelDocument",
    "TargetPort",
    # Managers
    "NmapScanManager",
    "NiktoScanManager",
    "OpenVASScanManager",
    "ScanManager",
    # Repositories
    "ScanRepository",
    "SentinelReportRepository",
    # Endpoints
    "sentinel_bp",
    # Reports
    "PDFCreator",
    "NmapPrintingStrategy",
    "NiktoPrintingStrategy",
    "OpenVASPrintingStrategy",
]