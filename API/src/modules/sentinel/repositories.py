"""
Repositories for the Sentinel security scanning module.

Provides typed data access for Scan, its polymorphic subtypes
(NmapScan, NiktoScan, OpenVASScan), and SentinelDocument.

Classes:
    ScanRepository:                Repository for Scan and its polymorphic subtypes.
    SentinelDocumentRepository:    Repository for SentinelDocument (PDF reports).

Usage:
    with UnitOfWork() as uow:
        scan_repo = ScanRepository(uow)
        doc_repo  = SentinelDocumentRepository(uow)

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

from src.modules.sentinel.model import (
    NiktoScan,
    NmapScan,
    OpenPort,
    OpenVASScan,
    OpenVASScanResult,
    Scan,
    ScanStatus,
    SentinelDocument,
)
from src.modules.infrastructure.base_repository import BaseRepository
from src.modules.infrastructure.unit_of_work import UnitOfWork


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

    def get_nmap_by_id(self, scan_id: int) -> Optional[NmapScan]:
        return self._session.get(NmapScan, scan_id)

    def get_nikto_by_id(self, scan_id: int) -> Optional[NiktoScan]:
        return self._session.get(NiktoScan, scan_id)

    def get_openvas_by_id(self, scan_id: int) -> Optional[OpenVASScan]:
        return self._session.get(OpenVASScan, scan_id)

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

    def get_by_user_and_type(self, user_id: int, scan_type: str) -> List[Scan]:
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
        scan.status = status.value

        terminal = {ScanStatus.FINISHED, ScanStatus.FAILED, ScanStatus.CANCELLED}
        if status in terminal and scan.finished_at is None:
            scan.finished_at = datetime.utcnow()

        return self.update(scan)


class SentinelDocumentRepository(BaseRepository[SentinelDocument]):
    """
    Repository for the SentinelDocument entity (PDF reports).

    Attributes:
        _model:  SentinelDocument (inherited from BaseRepository).
        _uow:    Active Unit of Work (inherited from BaseRepository).

    Example:
    >>> with UnitOfWork() as uow:
    ...     repo = SentinelDocumentRepository(uow)
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
        doc.status = status
        if filename is not None:
            doc.filename = filename
        if status == "done":
            doc.generated_at = _dt.utcnow()
        return doc