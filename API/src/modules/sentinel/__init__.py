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

# Lazy imports to avoid circular import
def get_sentinel_endpoints():
    from .endpoints import sentinel_bp
    return sentinel_bp

def get_processors():
    from .processors import (
        NmapResultProcessor,
        NiktoResultProcessor,
        OpenVASResultProcessor,
    )
    return NmapResultProcessor, NiktoResultProcessor, OpenVASResultProcessor

def get_tasks():
    from .tasks import (
        NiktoScanTask,
        NmapScanTask,
        OpenVASTask,
        TaskStatus,
        _Task,
    )
    return NiktoScanTask, NmapScanTask, OpenVASTask, TaskStatus, _Task

def get_reports():
    from .reports import (
        PDFCreator,
        NmapPrintingStrategy,
        NiktoPrintingStrategy,
        OpenVASPrintingStrategy,
    )
    return PDFCreator, NmapPrintingStrategy, NiktoPrintingStrategy, OpenVASPrintingStrategy


# For backwards compatibility
sentinel_bp = None
NmapResultProcessor = None
NiktoResultProcessor = None
OpenVASResultProcessor = None
NiktoScanTask = None
NmapScanTask = None
OpenVASTask = None
TaskStatus = None
_Task = None
PDFCreator = None
NmapPrintingStrategy = None
NiktoPrintingStrategy = None
OpenVASPrintingStrategy = None

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
    # Endpoints
    "sentinel_bp",
    # Processors
    "NmapResultProcessor",
    "NiktoResultProcessor",
    "OpenVASResultProcessor",
    # Tasks
    "NiktoScanTask",
    "NmapScanTask",
    "OpenVASTask",
    "TaskStatus",
    "_Task",
    # Reports
    "PDFCreator",
    "NmapPrintingStrategy",
    "NiktoPrintingStrategy",
    "OpenVASPrintingStrategy",
]