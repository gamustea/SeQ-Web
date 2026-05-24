
from datetime import datetime, timedelta
from typing import Any, Callable, Optional

from apscheduler.schedulers.background import BackgroundScheduler as _BgScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from croniter import croniter

from src.modules.infrastructure import UnitOfWork
from src.modules.system.logging import SecOpsLogger

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

    _scheduler: Optional[_BgScheduler] = None
    _logger = SecOpsLogger("Scheduler").get_logger()

    # =========================================================================
    # JOB HELPERS
    # =========================================================================

    @classmethod
    def _build_job_id(cls, ps_id: int) -> str:
        return f"programed_scan_{ps_id}"

    @classmethod
    def _build_trigger(cls, schedule_type: str, schedule_config: dict):
        if schedule_type == "interval":
            every = int(schedule_config["every"])
            unit = schedule_config["unit"]
            return IntervalTrigger(**{unit: every})
        elif schedule_type == "cron":
            return CronTrigger.from_crontab(schedule_config["cron"])
        else:
            raise ValueError(f"Unknown schedule_type: {schedule_type}")

    # =========================================================================
    # LIFECYCLE
    # =========================================================================

    @classmethod
    def start(cls) -> None:
        if cls._scheduler is not None:
            return
        cls._scheduler = _BgScheduler()
        cls._scheduler.start()
        cls._logger.info("Scheduler started")
        cls._sync_from_db()

    @classmethod
    def stop(cls) -> None:
        if cls._scheduler is None:
            return
        cls._scheduler.shutdown(wait=True)
        cls._scheduler = None
        cls._logger.info("Scheduler stopped")

    # =========================================================================
    # JOB MANAGEMENT
    # =========================================================================

    @classmethod
    def schedule(cls, ps: ProgramedScan) -> None:
        if cls._scheduler is None:
            cls._logger.warning("Scheduler not started, skipping schedule")
            return

        job_id = cls._build_job_id(ps.id) # type: ignore
        job_name = f"{ps.scan_type} scan (user {ps.user_id})"
        trigger = cls._build_trigger(
            ps.schedule_type, # type: ignore
            ps.schedule_config # type: ignore
        )
        cls._scheduler.add_job(
            func=cls.execute,
            trigger=trigger,
            args=[ps.id],
            id=job_id,
            replace_existing=True,
            max_instances=1,
            name=job_name,
        )
        cls._logger.info(f"Scheduled scan {ps.id}: {ps.scan_type} ({ps.schedule_type})")

    @classmethod
    def unschedule(cls, ps_id: int) -> None:
        if cls._scheduler is None:
            return
        job = cls._scheduler.get_job(cls._build_job_id(ps_id))
        if job is not None:
            job.remove()
            cls._logger.info(f"Unscheduled scan {ps_id}")

    # =========================================================================
    # INTERNALS
    # =========================================================================

    @classmethod
    def _sync_from_db(cls) -> None:
        if cls._scheduler is None:
            return
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            active = repo.get_all_active()
            for ps in active:
                cls.schedule(ps)
            cls._logger.info(f"Synced {len(active)} active scans from database")

    # =========================================================================
    # EXECUTION
    # =========================================================================

    @classmethod
    def execute(cls, ps_id: int) -> None:
        cls._logger.info(f"Triggered scan {ps_id}")
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            ps = repo.get_by_id(ps_id)

            if ps is None:
                raise ProgramedScanNotFoundError(ps_id)

            run_scan = cls._TASK_MAPPING.get(ScanType(ps.scan_type))
            if run_scan is None:
                raise ValueError(f"Unknown scan type: {ps.scan_type}")

            run_scan(
                ps,
                ps.arguments # type: ignore
            )
            repo.update_last_run(ps)
            next_run = cls.calculate_next_run(
                schedule_type=ps.schedule_type, # type: ignore
                schedule_config=ps.schedule_config, # type: ignore
                last_run=ps.last_run_at, # type: ignore
            )
            repo.update_next_run(ps, next_run)

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
