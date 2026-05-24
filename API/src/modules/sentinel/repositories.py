"""
Repositories for the Sentinel security scanning module.

Provides typed data access for Scan, its polymorphic subtypes
(NmapScan, NiktoScan, OpenVASScan), and SentinelDocument.

Classes:
    ScanRepository:                Repository for Scan and its polymorphic subtypes.
    SentinelReportRepository:    Repository for SentinelDocument (PDF reports).

Usage:
    with UnitOfWork() as uow:
        scan_repo = ScanRepository(uow)
        doc_repo  = SentinelReportRepository(uow)

        scan = scan_repo.get_by_id(42)
        docs = doc_repo.get_documents_by_user(user_id=1)

        # Persist
        scan_repo.save(NmapScan(target="10.0.0.1", user_id=1))

        # Commits automatically on context-manager exit.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import joinedload
from src.modules.infrastructure import BaseRepository, UnitOfWork

from .model import (
    Host,
    NiktoIncident,
    NiktoScan,
    NmapScan,
    OpenPort,
    OpenVASVulnerability,
    OpenVASScan,
    OpenVASScanResult,
    Port,
    ProgramedScan,
    Scan,
    ScanStatus,
    ScanType,
    SentinelDocument,
)


class ScanRepository(BaseRepository[Scan]):
    """
    Repository for the Scan entity and its polymorphic subtypes.

    Inherits all generic CRUD and query operations from BaseRepository[Scan]
    and adds domain-specific query methods for the Sentinel module.

    Polymorphism is handled transparently by SQLAlchemy: querying Scan
    returns instances of NmapScan, NiktoScan, or OpenVASScan depending
    on the `scan_type` discriminator column.

    Attributes:
        _model:  Scan (inherited from BaseRepository).
        _uow:    Active Unit of Work (inherited from BaseRepository).

    Example:
    >>> with UnitOfWork() as uow:
    ...     repo = ScanRepository(uow)
    ...     scan = NmapScan(target="192.168.1.1", user_id=1)
    ...     repo.save(scan)
    """

    def __init__(self, uow: UnitOfWork) -> None:
        super().__init__(Scan, uow)

    # =========================================================================
    # TYPED GETTERS BY SUBTYPE
    # =========================================================================

    def get_by_id_and_type(self, scan_type: type[Scan], scan_id: int):
        return self._session.get(scan_type, scan_id)

    def get_nmap_by_id(self, scan_id: int) -> Optional[NmapScan]:
        return self.get_by_id_and_type(NmapScan, scan_id)

    def get_nikto_by_id(self, scan_id: int) -> Optional[NiktoScan]:
        return self.get_by_id_and_type(NiktoScan, scan_id)

    def get_openvas_by_id(self, scan_id: int) -> Optional[OpenVASScan]:
        return self.get_by_id_and_type(OpenVASScan, scan_id)

    # =========================================================================
    # EAGER-LOADED QUERIES (for detached object usage, e.g. PDF generation)
    # =========================================================================

    def get_nmap_rich(self, scan_id: int) -> Optional[NmapScan]:
        return (
            self._session.query(NmapScan)
            .filter(NmapScan.id == scan_id)
            .options(
                joinedload(NmapScan.open_ports_relation).joinedload(OpenPort.port),
                joinedload(NmapScan.host),
            )
            .one_or_none()
        )

    def get_nikto_rich(self, scan_id: int) -> Optional[NiktoScan]:
        return (
            self._session.query(NiktoScan)
            .filter(NiktoScan.id == scan_id)
            .options(joinedload(NiktoScan.incidents), joinedload(NiktoScan.host))
            .one_or_none()
        )

    def get_openvas_rich(self, scan_id: int) -> Optional[OpenVASScan]:
        return (
            self._session.query(OpenVASScan)
            .filter(OpenVASScan.id == scan_id)
            .options(
                joinedload(OpenVASScan.host),
                joinedload(OpenVASScan.results).joinedload(OpenVASScanResult.vulnerability),
                joinedload(OpenVASScan.results).joinedload(OpenVASScanResult.host),
            )
            .one_or_none()
        )

    def get_nmap_by_user(self, user_id: int) -> List[NmapScan]:
        return (
            self._session.query(NmapScan)
            .filter(NmapScan.user_id == user_id)
            .options(
                joinedload(NmapScan.open_ports_relation).joinedload(OpenPort.port),
                joinedload(NmapScan.host),
            )
            .all()
        )

    def get_nikto_by_user(self, user_id: int) -> List[NiktoScan]:
        return (
            self._session.query(NiktoScan)
            .filter(NiktoScan.user_id == user_id)
            .options(joinedload(NiktoScan.incidents), joinedload(NiktoScan.host))
            .all()
        )

    def get_openvas_by_user(self, user_id: int) -> List[OpenVASScan]:
        return (
            self._session.query(OpenVASScan)
            .filter(OpenVASScan.user_id == user_id)
            .options(
                joinedload(OpenVASScan.results).joinedload(OpenVASScanResult.vulnerability),
                joinedload(OpenVASScan.results).joinedload(OpenVASScanResult.host),
            )
            .all()
        )

    # =========================================================================
    # DOMAIN QUERIES
    # =========================================================================

    def get_by_user(self, user_id: int) -> List[Scan]:
        return (
            self._session.query(Scan)
            .filter(Scan.user_id == user_id)
            .order_by(Scan.started_at.desc())
            .all()
        )

    def get_by_user_and_type(self, user_id: int, scan_type: ScanType) -> List[Scan]:
        return (
            self._session.query(Scan)
            .filter(Scan.user_id == user_id, Scan.scan_type == scan_type)
            .options(joinedload(Scan.host))
            .order_by(Scan.started_at.desc())
            .all()
        )

    def get_by_target(self, target: str) -> List[Scan]:
        return self.get_all_by_field("target", target)

    def get_by_status(self, status: ScanStatus) -> List[Scan]:
        return (
            self._session.query(Scan)
            .filter(Scan.status == status.value)
            .all()
        )

    def get_active_scans(self) -> List[Scan]:
        return (
            self._session.query(Scan)
            .filter(
                Scan.status.in_([ScanStatus.PENDING.value, ScanStatus.RUNNING.value])
            )
            .order_by(Scan.started_at.asc())
            .all()
        )

    def get_frequent_scans(self, user_id: int) -> List[Scan]:
        return (
            self._session.query(Scan)
            .filter(Scan.user_id == user_id, Scan.frecuent.is_(True))
            .all()
        )

    def get_by_host(self, host_id: int) -> List[Scan]:
        return self.get_all_by_field("host_id", host_id)

    # =========================================================================
    # STATUS TRANSITIONS
    # =========================================================================

    def update_status(self, scan: Scan, status: ScanStatus) -> Scan:
        scan.status = status.value # type: ignore

        terminal = {ScanStatus.FINISHED, ScanStatus.FAILED, ScanStatus.CANCELLED}
        if status in terminal and scan.finished_at is None:
            scan.finished_at = datetime.utcnow() # type: ignore

        return self.update(scan)

    def get_or_create_host(
        self,
        hostname: str,
        ip_address: str,
        mac_address: str = "",
        vendor: str = ""
    ) -> Host:
        """Get or create a Host row using upsert to avoid race conditions."""
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        host = self._session.query(Host).filter(Host.hostname == hostname).first()
        if host:
            return host

        stmt = pg_insert(Host).values(
            hostname    = hostname,
            ip_address  = ip_address,
            mac_address = mac_address or "",
            vendor      = vendor,
        ).on_conflict_do_nothing(index_elements=["hostname"])

        self._session.execute(stmt)
        self._session.flush()

        return self._session.query(Host).filter(Host.hostname == hostname).first()

    def get_or_create_port(self, protocol: str) -> Port:
        """Get or create a Port row by its protocol string."""
        port = self._session.query(Port).filter(Port.protocol == protocol).one_or_none()
        if port:
            return port

        new_port = Port(protocol=protocol)
        self._session.add(new_port)
        self._session.flush()
        return new_port

    def get_or_create_nikto_incident(self, inc_data: dict) -> NiktoIncident:
        """Get or create a NiktoIncident row by its unique fields."""
        existing = self._session.query(NiktoIncident).filter(
            NiktoIncident.description == inc_data["description"],
            NiktoIncident.url         == inc_data["url"],
            NiktoIncident.method      == inc_data["method"],
        ).first()

        if existing:
            return existing

        incident = NiktoIncident(
            description = inc_data["description"],
            osvdb_id    = inc_data["osvdb_id"],
            method      = inc_data["method"],
            url         = inc_data["url"],
            severity    = inc_data["severity"],
        )
        self._session.add(incident)
        self._session.flush()
        return incident

    def get_or_create_vulnerability(self, vuln_data: dict) -> OpenVASVulnerability:
        """Get or create an OpenVASVulnerability row by NVT OID."""
        nvt_oid = vuln_data["nvt_oid"]
        vuln = self._session.query(OpenVASVulnerability).filter(
            OpenVASVulnerability.nvt_oid == nvt_oid
        ).one_or_none()

        if vuln:
            return vuln

        vuln = OpenVASVulnerability(**vuln_data)
        self._session.add(vuln)
        self._session.flush()
        return vuln

    def persist_nmap_results(self, scan, host, ports_data) -> None:
        """Persist Nmap host and port data into the database."""
        scan.host_id = host.id

        for port_info in ports_data:
            port = self.get_or_create_port(port_info["protocol"])
            if port not in scan.target_ports:
                scan.target_ports.append(port)

            open_port = OpenPort(
                nmap_scan_id = scan.id,
                port_id      = port.id,
                reason       = port_info["reason"],
                product      = port_info["product"],
                version      = port_info["version"],
                given_use    = port_info["given_use"],
            )
            self._session.add(open_port)

    def persist_nikto_results(self, scan, host, incidents_data) -> None:
        """Persist Nikto incidents and associate a host."""
        for inc_data in incidents_data:
            incident = self.get_or_create_nikto_incident(inc_data)
            if incident not in scan.incidents:
                scan.incidents.append(incident)

        scan.host = host

    def persist_openvas_results(self, scan, results_data, vulnerability_map) -> None:
        """Persist OpenVAS scan results."""
        for result_data in results_data:
            host = self.get_or_create_host(
                hostname   = result_data["host_ip"],
                ip_address = result_data["host_ip"],
            )

            scan_result = OpenVASScanResult(
                openvas_scan_id  = scan.id,
                vulnerability_id = vulnerability_map[result_data["nvt_oid"]].id,
                host_id          = host.id,
            )
            self._session.add(scan_result)


class SentinelReportRepository(BaseRepository[SentinelDocument]):
    """
    Repository for the SentinelDocument entity (PDF reports).

    Attributes:
        _model:  SentinelDocument (inherited from BaseRepository).
        _uow:    Active Unit of Work (inherited from BaseRepository).

    Example:
    >>> with UnitOfWork() as uow:
    ...     repo = SentinelReportRepository(uow)
    ...     doc  = repo.get_by_id(1)
    ...     repo.delete(doc)
    """

    def __init__(self, uow: UnitOfWork) -> None:
        super().__init__(SentinelDocument, uow)

    def get_document(self, scan_id: int) -> Optional[SentinelDocument]:
        return (
            self._session.query(SentinelDocument)
            .filter(SentinelDocument.scan_id == scan_id)
            .one_or_none()
        )

    def get_latest_document(self, scan_id: int) -> Optional[SentinelDocument]:
        return (
            self._session.query(SentinelDocument)
            .filter(SentinelDocument.scan_id == scan_id)
            .order_by(SentinelDocument.created_at.desc())
            .first()
        )

    def get_documents_by_user(self, user_id: int) -> List[SentinelDocument]:
        return (
            self._session.query(SentinelDocument)
            .filter(SentinelDocument.user_id == user_id)
            .order_by(SentinelDocument.created_at.desc())
            .all()
        )

    def get_documents_by_scan(self, scan_id: int) -> List[SentinelDocument]:
        return (
            self._session.query(SentinelDocument)
            .filter(SentinelDocument.scan_id == scan_id)
            .order_by(SentinelDocument.created_at.desc())
            .all()
        )

    def get_by_id_with_details(self, doc_id: int) -> Optional[SentinelDocument]:
        """
        Retrieve a document with all its relationships eager-loaded.

        Loads: user, scan.

        Args:
            doc_id: Primary key of the document.

        Returns:
            SentinelDocument with relationships loaded, or None if not found.
        """
        return (
            self._session.query(SentinelDocument)
            .filter(SentinelDocument.id == doc_id)
            .options(
                joinedload(SentinelDocument.user),
                joinedload(SentinelDocument.scan),
            )
            .one_or_none()
        )

    def update_status(self, document_id: int, status: str, filename: Optional[str] = None) -> Optional[SentinelDocument]:
        doc = self._session.get(SentinelDocument, document_id)
        if doc is None:
            return None

        from datetime import datetime as _dt
        doc.status = status # type: ignore
        if filename is not None:
            doc.filename = filename # type: ignore
        if status == "done":
            doc.generated_at = _dt.utcnow() # type: ignore
        return doc


class ProgramedScanRepository(BaseRepository[ProgramedScan]):
    """
    Repository for the ProgramedScan entity (scheduled/recurring scans).

    Manages programed scan lifecycle: querying by user and type,
    finding due executions for the scheduler, and recording run timestamps.

    Attributes:
        _model:  ProgramedScan (inherited from BaseRepository).
        _uow:    Active Unit of Work (inherited from BaseRepository).

    Example:
    >>> with UnitOfWork() as uow:
    ...     repo = ProgramedScanRepository(uow)
    ...     due_scans = repo.get_due()
    ...     for ps in due_scans:
    ...         repo.update_last_run(ps)
    """

    def __init__(self, uow: UnitOfWork) -> None:
        super().__init__(ProgramedScan, uow)

    # =========================================================================
    # QUERY METHODS
    # =========================================================================

    def get_by_user(self, user_id: int) -> List[ProgramedScan]:
        """
        Retrieve all programed scans for a user, ordered by creation date.

        Args:
            user_id: User primary key.

        Returns:
            List of ProgramedScan instances sorted newest‑first.
        """
        return (
            self._session.query(ProgramedScan)
            .filter(ProgramedScan.user_id == user_id)
            .order_by(ProgramedScan.created_at.desc())
            .all()
        )

    def get_active_by_user(self, user_id: int) -> List[ProgramedScan]:
        """
        Retrieve active programed scans for a user.

        Args:
            user_id: User primary key.

        Returns:
            List of active ProgramedScan instances.
        """
        return (
            self._session.query(ProgramedScan)
            .filter(
                ProgramedScan.user_id == user_id,
                ProgramedScan.is_active.is_(True),
            )
            .order_by(ProgramedScan.created_at.desc())
            .all()
        )

    def get_by_user_and_type(self, user_id: int, scan_type: ScanType) -> List[ProgramedScan]:
        """
        Retrieve programed scans for a user filtered by scan type.

        Args:
            user_id:    User primary key.
            scan_type:  Scan type discriminator ("nmap", "nikto", "openvas").

        Returns:
            List of matching ProgramedScan instances.
        """
        return (
            self._session.query(ProgramedScan)
            .filter(
                ProgramedScan.user_id == user_id,
                ProgramedScan.scan_type == scan_type,
            )
            .order_by(ProgramedScan.created_at.desc())
            .all()
        )

    def get_due(self) -> List[ProgramedScan]:
        """
        Retrieve all active programed scans whose next_run_at is in the past.

        Used by the scheduler to find scans that are due for execution. Only
        returns scans that have both is_active=True and next_run_at populated.

        Returns:
            List of ProgramedScan instances that need to run.
        """
        return (
            self._session.query(ProgramedScan)
            .filter(
                ProgramedScan.is_active.is_(True),
                ProgramedScan.next_run_at.isnot(None),
                ProgramedScan.next_run_at <= datetime.utcnow(),  # type: ignore
            )
            .all()
        )

    def get_all_active(self) -> List[ProgramedScan]:
        """
        Retrieve all active programed scans regardless of user.

        Used on scheduler startup to restore all scheduled jobs from the
        database after a restart.

        Returns:
            List of active ProgramedScan instances.
        """
        return (
            self._session.query(ProgramedScan)
            .filter(ProgramedScan.is_active.is_(True))
            .order_by(ProgramedScan.created_at.desc())
            .all()
        )

    # =========================================================================
    # MUTATION METHODS
    # =========================================================================

    def update_last_run(self, ps: ProgramedScan) -> ProgramedScan:
        """
        Record that a programed scan has just executed.

        Sets last_run_at to the current UTC time and persists the change
        so the scheduler can track execution history.

        Args:
            ps: The ProgramedScan that executed.

        Returns:
            The same ProgramedScan instance after flush.
        """
        ps.last_run_at = datetime.utcnow()  # type: ignore
        return self.update(ps)

    def update_next_run(
        self,
        ps: ProgramedScan,
        next_run_at: datetime
    ) -> ProgramedScan:
        ps.next_run_at = next_run_at   # type: ignore
        return self.update(ps)

    def create(
        self,
        user_id: int,
        scan_type: ScanType,
        arguments: dict,
        schedule_type: str,
        schedule_config: dict,
    ) -> ProgramedScan:
        """
        Create and persist a new programed scan.

        Args:
            user_id:         Owner user primary key.
            scan_type:       Scan discriminator ("nmap", "nikto", "openvas").
            arguments:       Scan parameters (e.g. {"ports": "22,80"}).
            schedule_type:   "interval" or "cron".
            schedule_config: Schedule definition (e.g. {"every": 60, "unit": "minutes"}).

        Returns:
            The newly persisted ProgramedScan instance.
        """
        ps = ProgramedScan(
            user_id=user_id,
            scan_type=scan_type,
            arguments=arguments,
            schedule_type=schedule_type,
            schedule_config=schedule_config,
        )
        return self.save(ps)

    def delete_by_id(self, pk: int) -> bool:
        """
        Delete a programed scan by primary key.

        Args:
            pk: ProgramedScan primary key.

        Returns:
            True if a row was deleted, False if no row matched.
        """
        ps = self.get_by_id(pk)
        if ps is None:
            return False
        self.delete(ps)
        return True