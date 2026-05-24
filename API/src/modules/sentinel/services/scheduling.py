

from datetime import datetime, timedelta
from typing import Any, Callable, Optional

from croniter import croniter

from src.modules.infrastructure import UnitOfWork

from ..exceptions import (
    InvalidProgramedTaskArgumentError,
    ProgramedScanNotFoundError,
)
from ..repositories import ProgramedScanRepository
from ..model import ProgramedScan, ScanType


def _require_args(
    arguments: dict[str, Any],
    required: list[str],
    scan_type: str,
) -> None:
    for field in required:
        if arguments.get(field) is None:
            raise InvalidProgramedTaskArgumentError(scan_type, field)

def _run_nmap_scan(ps: ProgramedScan, arguments: dict[str, Any]) -> None:
    _require_args(arguments, ["target_host", "target_ports"], "nmap")

    from ..managers import NmapScanManager

    manager = NmapScanManager()
    manager.run_scan(
        target_host=arguments["target_host"],
        target_ports=arguments["target_ports"],
        user_id=ps.user_id,
    )

def _run_nikto_scan(ps: ProgramedScan, arguments: dict[str, Any]) -> None:
    _require_args(arguments, ["target_domain"], "nikto")

    from ..managers import NiktoScanManager

    manager = NiktoScanManager()
    manager.run_scan(
        target_domain=arguments["target_domain"],
        user_id=ps.user_id,
    )

def _run_openvas_scan(ps: ProgramedScan, arguments: dict[str, Any]) -> None:
    _require_args(arguments, ["target"], "openvas")

    from ..managers import OpenVASScanManager

    manager = OpenVASScanManager()
    manager.run_scan(
        target=arguments["target"],
        user_id=ps.user_id,
    )


class Scheduler:

    _TASK_MAPPING: dict[ScanType, Callable[[ProgramedScan, dict[str, Any]], None]] = {
        ScanType.NMAP:    _run_nmap_scan,
        ScanType.NIKTO:   _run_nikto_scan,
        ScanType.OPENVAS: _run_openvas_scan,
    }

    @classmethod
    def execute(cls, ps_id: int) -> None:
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            ps = repo.get_by_id(ps_id)

            if ps is None:
                raise ProgramedScanNotFoundError(ps_id)

            arguments = ps.arguments

            handler = cls._TASK_MAPPING.get(ScanType(ps.scan_type))
            if handler is None:
                raise ValueError(f"Unknown scan type: {ps.scan_type}")

            handler(ps, arguments) # type: ignore
            repo.update_last_run(ps)

    @classmethod
    def calculate_next_run(
        cls,
        schedule_type: str,
        schedule_config: dict,
        last_run: Optional[datetime] = None,
    ) -> datetime:
        reference = last_run if last_run is not None else datetime.utcnow()

        if schedule_type == "interval":
            every = int(schedule_config["every"])
            unit = schedule_config["unit"]

            if unit == "minutes":
                delta = timedelta(minutes=every)
            elif unit == "hours":
                delta = timedelta(hours=every)
            elif unit == "days":
                delta = timedelta(days=every)
            else:
                raise ValueError(f"Unknown interval unit: {unit}")

            return reference + delta

        elif schedule_type == "cron":
            cron_expr = schedule_config["cron"]
            iter_ = croniter(cron_expr, reference)
            return iter_.get_next(datetime)

        else:
            raise ValueError(f"Unknown schedule_type: {schedule_type}")
