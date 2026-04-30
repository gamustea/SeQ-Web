"""
Managers for security scan orchestration and result persistence.

This module provides manager classes for coordinating security scans:
- NmapScanManager: Network exploration and security scanning.
- NiktoScanManager: Web server vulnerability scanning.
- OpenVASScanManager: Comprehensive vulnerability management.

Each manager handles the complete lifecycle of a scan:
- Creating scan records via ScanRepository.
- Executing scans in background threads.
- Processing and saving results.
- Generating PDF reports asynchronously.

Database access is performed exclusively through UnitOfWork + ScanRepository.
ScanManager no longer inherits from BaseManager.

Usage:
    manager = NmapScanManager(user)
    scan_id = manager.run_scan(target_host="192.168.1.1", target_ports="1-1000")
    scan = manager.get_scan_by_id(scan_id)
"""

import os
import threading
import uuid
import src.modules.system.config_reading as CR

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional

from src.modules.users import User
from src.modules.shared import normalize_target
from src.modules.system.logging import SecOpsLogger
from src.modules.exceptions.documents import DocumentError

from src.modules.infrastructure.unit_of_work import UnitOfWork
from .repositories import ScanRepository, SentinelDocumentRepository

from .model import (
    Host,
    NiktoIncident,
    NiktoScan,
    NmapScan,
    OpenPort,
    OpenVASScan,
    OpenVASScanResult,
    Scan,
    ScanStatus,
    SentinelDocument,
)
from .processors import (
    NiktoResultProcessor,
    NmapResultProcessor,
    OpenVASResultProcessor,
    ScanResultProcessor,
)
from .reports import NiktoPrintingStrategy, NmapPrintingStrategy, OpenVASPrintingStrategy, PDFCreator
from .tasks import NiktoScanTask, NmapScanTask, OpenVASTask, TaskStatus, _Task


class ScanManager(ABC):
    """
    Base class for scan managers.

    Coordinates task execution and result persistence without inheriting from
    BaseManager. All database access is performed through UnitOfWork and
    ScanRepository, keeping transaction boundaries explicit.

    Class Attributes:
        _running_tasks:       Dictionary mapping scan_id to running _Task.
        _running_threads:     Dictionary mapping scan_id to running Thread.
        _running_tasks_lock:  RLock for thread-safe task management.

    Attributes:
        active_user: User executing the scan operations.
        logger:      Logger instance for this manager.
    """

    _running_tasks: Dict[int, _Task] = {}
    _running_threads: Dict[int, threading.Thread] = {}
    _running_tasks_lock = threading.RLock()

    def __init__(self, user: User) -> None:
        """
        Initialize the scan manager.

        Args:
            user: User performing the scan operations.
        """
        self.active_user = user
        self.logger = SecOpsLogger(self.__class__.__name__).get_logger()

    # =========================================================================
    # TASK REGISTRY (class-level, thread-safe)
    # =========================================================================

    @classmethod
    def _register_task(cls, scan_id: int, task: _Task, thread: Optional[threading.Thread] = None) -> None:
        """Register a running task and its thread."""
        with cls._running_tasks_lock:
            cls._running_tasks[scan_id] = task
            if thread is not None:
                cls._running_threads[scan_id] = thread

    @classmethod
    def _get_task(cls, scan_id: int) -> Optional[_Task]:
        """Return the registered task for a scan, or None."""
        with cls._running_tasks_lock:
            return cls._running_tasks.get(scan_id)

    @classmethod
    def _unregister_task(cls, scan_id: int) -> None:
        """Remove a task and its thread from the registry."""
        with cls._running_tasks_lock:
            cls._running_tasks.pop(scan_id, None)
            cls._running_threads.pop(scan_id, None)

    @classmethod
    def cancel_all_running(cls, timeout: float = 10.0) -> None:
        """
        Cancel all running tasks and wait for threads to finish.

        Intended to be called from the shutdown signal handler.

        Args:
            timeout: Maximum time to wait for each thread to join.
        """
        with cls._running_tasks_lock:
            task_snapshot   = dict(cls._running_tasks)
            thread_snapshot = dict(cls._running_threads)

        for task in task_snapshot.values():
            try:
                task.cancel()
            except Exception:
                pass

        for thread in thread_snapshot.values():
            thread.join(timeout=timeout)

    # =========================================================================
    # COMMON SCAN QUERIES
    # =========================================================================

    def get_scan_by_id(self, scan_id: int) -> Optional[Scan]:
        """
        Retrieve a scan by its primary key.

        Args:
            scan_id: Primary key of the scan.

        Returns:
            Scan instance (polymorphic subtype), or None if not found.
        """
        with UnitOfWork() as uow:
            scan = ScanRepository(uow).get_by_id(scan_id)

        if scan:
            self.logger.info(f"Escaneo {scan_id} encontrado")
        else:
            self.logger.warning(f"Escaneo {scan_id} no encontrado")

        return scan

    def get_scans_for_user(self) -> List[Scan]:
        """
        Retrieve all scans belonging to the active user.

        Subclasses override this to apply joinedload for type-specific
        relationships (open_ports_relation, incidents, results…).

        Returns:
            List of Scan instances ordered by start time descending.
        """
        with UnitOfWork() as uow:
            scans = ScanRepository(uow).get_by_user(self.active_user.id)

        self.logger.info(f"Se obtuvieron {len(scans)} escaneos para el usuario {self.active_user.id}")
        return scans

    def is_scan_finished(self, scan_id: int) -> bool:
        """
        Check whether a scan has reached FINISHED status.

        Args:
            scan_id: Primary key of the scan.

        Returns:
            True if status == FINISHED, False otherwise (including not found).
        """
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            self.logger.warning(f"Escaneo {scan_id} no encontrado para verificar finalización")
            return False

        return scan.status == ScanStatus.FINISHED.value

    def get_scan_progress(self, scan_id: int) -> Optional[int]:
        """
        Return the progress percentage (0-100) of a running scan.

        Args:
            scan_id: Primary key of the scan.

        Returns:
            Integer percentage, or None if the scan is not in the task registry.
        """
        task = self._get_task(scan_id)
        if task:
            self.logger.debug(f"Progreso de escaneo {scan_id}: {task.progress}%")
            return task.progress
        return None

    def get_scan_status(self, scan_id: int) -> Optional[str]:
        """
        Return the current status string of a scan.

        Checks the in-memory task registry first; falls back to the database.

        Args:
            scan_id: Primary key of the scan.

        Returns:
            Status string, or None if not found.
        """
        task = self._get_task(scan_id)
        if task:
            return str(task.status)
        if self.is_scan_finished(scan_id):
            return str(TaskStatus.COMPLETED)
        return None

    
    # =========================================================================
    # DOCUMENT QUERIES
    # =========================================================================

    def get_document_by_id(self, document_id: int) -> Optional[SentinelDocument]:
        """
        Retrieve a SentinelDocument by its primary key.

        Args:
            document_id: Primary key of the document.

        Returns:
            SentinelDocument instance, or None.
        """
        with UnitOfWork() as uow:
            doc_repo = SentinelDocumentRepository(uow)
            doc = doc_repo.get_by_id(document_id)

        if not doc:
            self.logger.warning(f"Documento {document_id} no encontrado")

        return doc

    def get_latest_document_by_scan_id(self, scan_id: int) -> Optional[SentinelDocument]:
        """
        Retrieve the most recently created document for a scan.

        Args:
            scan_id: Primary key of the scan.

        Returns:
            SentinelDocument instance, or None.
        """
        with UnitOfWork() as uow:
            doc = SentinelDocumentRepository(uow).get_latest_document(scan_id)

        if doc:
            self.logger.info(f"Último documento para scan {scan_id}: {doc.id}")
        else:
            self.logger.warning(f"No hay documentos para scan {scan_id}")

        return doc

    def get_documents_for_user(self) -> List[SentinelDocument]:
        """
        Retrieve all documents belonging to the active user.

        Returns:
            List of SentinelDocument instances, ordered by creation date descending.
        """
        with UnitOfWork() as uow:
            docs = SentinelDocumentRepository(uow).get_documents_by_user(self.active_user.id)

        self.logger.info(f"Se obtuvieron {len(docs)} documentos")
        return docs

    def get_documents_by_scan_id(self, scan_id: int) -> List[SentinelDocument]:
        """
        Retrieve all documents associated with a specific scan.

        Args:
            scan_id: Primary key of the scan.

        Returns:
            List of SentinelDocument instances, ordered by creation date descending.
        """
        with UnitOfWork() as uow:
            docs = SentinelDocumentRepository(uow).get_documents_by_scan(scan_id)

        self.logger.info(f"Se obtuvieron {len(docs)} documentos para scan {scan_id}")
        return docs

    def delete_document(self, document_id: int) -> bool:
        """
        Delete a scan and its associated documents.

        Args:
            scan_id: Primary key of the scan to delete.
        Returns:
            True if deleted successfully, False if the scan was not found.
            Raises: Exception if an error occurs during deletion.
        """

        with UnitOfWork() as uow:
            doc_repo = SentinelDocumentRepository(uow)
            doc = doc_repo.get_by_id(document_id)
            
            if not doc:
                raise DocumentError(f"Documento {document_id} no encontrado")
            
            scan_id = doc.scan_id
            if doc.filename and os.path.exists(doc.filename):
                try:
                    os.remove(doc.filename)
                except Exception as e:
                    self.logger.warning(f"No se pudo eliminar el archivo {doc.filename}: {e}")
            
            doc_repo.delete(doc)

        return True

    def check_ownership(self, document_id: int, user_id: int) -> bool:
        with UnitOfWork() as uow:
            doc_repo = SentinelDocumentRepository(uow)
            doc = doc_repo.get_by_id(document_id)
            if not doc:
                raise DocumentError(f"Documento {document_id} no encontrado")
            return doc.user_id == user_id

    # =========================================================================
    # LIFECYCLE OPERATIONS
    # =========================================================================

    def cancel_scan(self, scan_id: int) -> bool:
        """
        Cancel a running scan.

        Signals the in-memory task to stop and marks the scan as CANCELLED
        in the database.

        Args:
            scan_id: Primary key of the scan to cancel.

        Returns:
            True if cancelled successfully, False otherwise.
        """
        try:
            scan = self.get_scan_by_id(scan_id)
            if not scan:
                self.logger.warning(f"Escaneo {scan_id} no encontrado, no se puede cancelar")
                return False

            if scan.user_id != self.active_user.id:
                self.logger.warning(
                    f"El usuario {self.active_user.username} no tiene permisos "
                    f"para cancelar el escaneo {scan_id}"
                )
                return False

            if scan.status not in ("pending", "running"):
                self.logger.warning(
                    f"El escaneo {scan_id} no se puede cancelar "
                    f"(estado actual: {scan.status})"
                )
                return False

            task = self._get_task(scan_id)
            if task:
                try:
                    task.cancel()
                    self.logger.info(f"Tarea del escaneo {scan_id} cancelada")
                except Exception as e:
                    self.logger.error(f"Error cancelando tarea del escaneo {scan_id}: {e}")
                finally:
                    self._unregister_task(scan_id)
            else:
                self.logger.warning(f"No se encontró tarea en ejecución para el escaneo {scan_id}")
                return False

            with UnitOfWork() as uow:
                scan_repo = ScanRepository(uow)
                fresh_scan = scan_repo.get_by_id(scan_id)
                if fresh_scan:
                    scan_repo.update_status(fresh_scan, ScanStatus.CANCELLED)

            self.logger.info(f"Escaneo {scan_id} cancelado exitosamente")
            return True

        except Exception as e:
            self.logger.error(f"Error cancelando escaneo {scan_id}: {e}", exc_info=True)
            return False

    def delete_scan(self, scan_id: int) -> bool:
        """
        Delete a scan and its associated documents (including PDF files on disk).

        Args:
            scan_id: Primary key of the scan to delete.

        Returns:
            True if deleted successfully, False if the scan was not found.
        """
        try:
            with UnitOfWork() as uow:
                scan_repo = ScanRepository(uow)
                doc_repo = SentinelDocumentRepository(uow)

                scan = scan_repo.get_by_id(scan_id)
                if not scan:
                    return False

                docs = doc_repo.get_documents_by_scan(scan_id)

                for doc in docs:
                    if doc.filename and os.path.exists(doc.filename):
                        try:
                            os.remove(doc.filename)
                            self.logger.info(f"Archivo eliminado: {doc.filename}")
                        except Exception as e:
                            self.logger.warning(f"No se pudo eliminar archivo {doc.filename}: {e}")
                    doc_repo.delete(doc)

                scan_repo.delete(scan)
                # UnitOfWork commits on __exit__

            self.logger.info(f"Escaneo {scan_id} eliminado")
            return True

        except Exception as e:
            self.logger.error(f"Error eliminando escaneo {scan_id}: {e}")
            raise

    # =========================================================================
    # INTERNAL SCAN EXECUTION
    # =========================================================================

    def _execute_scan_in_thread(self, scan_id: int, task: _Task) -> None:
        """
        Execute a scan in a background thread and persist its results.

        Creates a fresh manager instance (and therefore a fresh session) for
        the thread so that SQLAlchemy sessions are not shared across threads.

        Args:
            scan_id: Primary key of the scan being executed.
            task:    Task instance that drives the actual scanning.
        """
        thread_manager = self.__class__(self.active_user)

        try:
            scan = thread_manager.get_scan_by_id(scan_id)
            if not scan:
                thread_manager.logger.error(f"Escaneo {scan_id} no encontrado en el hilo")
                return

            thread_manager.logger.info(f"Iniciando escaneo {scan_id}")

            TIME_MARGIN = 30
            task.scan()
            success = task.wait(timeout=task.timeout + TIME_MARGIN)

            if not success or task.results is None:
                thread_manager.logger.error(f"Escaneo {scan_id} falló. Estado: {task.status}")
                thread_manager._update_scan_status(scan_id, ScanStatus.FAILED)
                return

            thread_manager.logger.info(f"Procesando resultados de escaneo {scan_id}")

            processor  = thread_manager._get_result_processor()
            domain_data = thread_manager._extract_domain_data(processor, task, scan)

            with UnitOfWork() as uow:
                fresh_scan = ScanRepository(uow).get_by_id(scan_id)
                thread_manager._persist_scan_results(uow.session, fresh_scan, domain_data)
                fresh_scan.status     = ScanStatus.FINISHED.value
                fresh_scan.finished_at = datetime.now()

            thread_manager.logger.info(f"Escaneo {scan_id} completado exitosamente")

        except Exception as e:
            thread_manager.logger.error(f"Error en escaneo {scan_id}: {e}", exc_info=True)
            thread_manager._update_scan_status(scan_id, ScanStatus.FAILED)
        finally:
            self._unregister_task(scan_id)

    def _update_scan_status(self, scan_id: int, status: ScanStatus) -> None:
        """
        Persist a status change for a scan, ignoring errors (best-effort).

        Args:
            scan_id: Primary key of the scan.
            status:  New ScanStatus value.
        """
        try:
            with UnitOfWork() as uow:
                repo = ScanRepository(uow)
                scan = repo.get_by_id(scan_id)
                if scan:
                    repo.update_status(scan, status)
        except Exception as update_err:
            self.logger.error(f"Error actualizando estado de escaneo {scan_id}: {update_err}")

    def _mark_scan_as(self, scan: Scan, status: ScanStatus) -> None:
        """
        Update scan status and finished_at in-place (without committing).

        The caller is responsible for committing via its UnitOfWork.

        Args:
            scan:   Scan instance to update.
            status: New ScanStatus value.
        """
        old_status = scan.status
        scan.status     = status.value
        scan.finished_at = datetime.now()
        self.logger.info(
            f"Estado del escaneo {scan.id} actualizado: {old_status} -> {status.value}"
        )

    # =========================================================================
    # HOST HELPERS
    # =========================================================================

    def _get_or_create_host_in_session(self, session, hostname: str, ip_address: str,
                                       mac_address: str = "", vendor: str = "") -> Host:
        """
        Get or create a Host row within an existing session (no independent commit).

        Uses an upsert (INSERT … ON CONFLICT DO NOTHING) to avoid race conditions
        on the unique `hostname` column.

        Args:
            session:     Active SQLAlchemy session.
            hostname:    Unique hostname for the host.
            ip_address:  IP address of the host.
            mac_address: Optional MAC address.
            vendor:      Optional vendor string.

        Returns:
            Existing or newly created Host instance.
        """
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        host = session.query(Host).filter(Host.hostname == hostname).first()
        if host:
            return host

        stmt = pg_insert(Host).values(
            hostname    = hostname,
            ip_address  = ip_address,
            mac_address = mac_address or "",
            vendor      = vendor,
        ).on_conflict_do_nothing(index_elements=["hostname"])

        session.execute(stmt)
        session.flush()

        return session.query(Host).filter(Host.hostname == hostname).first()

    def _get_or_create_host_for_nikto(self, session, hostname: str, ip_address: str) -> Host:
        """
        Simplified host lookup/creation for Nikto scans (no MAC/vendor).

        Resolves the hostname to an IP via normalize_target before persisting.

        Args:
            session:    Active SQLAlchemy session.
            hostname:   Target as provided to the scan.
            ip_address: Fallback IP address.

        Returns:
            Existing or newly created Host instance.
        """
        ip, host = normalize_target(hostname, resolve_hostname=True)
        final_hostname = host or ip or hostname
        final_ip       = ip or ip_address

        existing = session.query(Host).filter(Host.hostname == final_hostname).first()
        if existing:
            return existing

        new_host = Host(hostname=final_hostname, ip_address=final_ip, mac_address="")
        session.add(new_host)
        session.flush()
        return new_host

    # =========================================================================
    # ABSTRACT INTERFACE
    # =========================================================================

    @abstractmethod
    def run_scan(self, **kwargs) -> int:
        """Start a new scan. Returns the scan's primary key."""
        pass

    @abstractmethod
    def _create_scan_record(self, **kwargs) -> Scan:
        """Create and persist the initial scan record."""
        pass

    @abstractmethod
    def _get_result_processor(self) -> ScanResultProcessor:
        """Return the result processor for this scan type."""
        pass

    @abstractmethod
    def generate_report(self, scan_id: int, ai_report: bool = False) -> int:
        """
        Create a SentinelDocument and start async PDF generation.

        Returns:
            Document primary key.
        """
        pass

    @abstractmethod
    def _extract_domain_data(self, processor, task, scan):
        """Extract structured domain data from the raw task results."""
        pass

    @abstractmethod
    def _persist_scan_results(self, session, scan, domain_data) -> None:
        """Persist domain data into the database within the given session."""
        pass


# =============================================================================
# NMAP
# =============================================================================

class NmapScanManager(ScanManager):
    """
    Manager for Nmap network security scans.

    Handles Nmap scan execution, result processing, and async PDF generation.

    Example:
    >>> manager = NmapScanManager(user)
    >>> scan_id = manager.run_scan(target_host="192.168.1.1", target_ports="1-1000")
    """

    def __init__(self, user: User) -> None:
        super().__init__(user)

    def run_scan(self, target_host: str, target_ports: str, timeout: int = 300) -> int:
        """
        Start an Nmap scan in a background thread.

        Args:
            target_host:  Target IP address or hostname.
            target_ports: Port range to scan (e.g., "1-1000").
            timeout:      Maximum scan duration in seconds.

        Returns:
            Primary key of the created NmapScan record.
        """
        try:
            scan    = self._create_scan_record(target=target_host)
            scan_id = scan.id

            task = NmapScanTask(
                target_host  = target_host,
                target_ports = target_ports,
                timeout      = timeout,
            )

            thread = threading.Thread(
                target = self._execute_scan_in_thread,
                args   = (scan_id, task),
                daemon = True,
                name   = f"NmapScan-{scan_id}",
            )

            self._register_task(scan_id, task, thread)
            thread.start()

            self.logger.info(f"Escaneo Nmap {scan_id} iniciado")
            return scan_id

        except Exception as e:
            self.logger.error(f"Error iniciando escaneo Nmap: {e}", exc_info=True)
            raise

    def _create_scan_record(self, target: str) -> NmapScan:
        """Create and persist an NmapScan row."""
        scan = NmapScan(target=target, user_id=self.active_user.id, started_at=datetime.now())
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
        return scan

    def _get_result_processor(self) -> NmapResultProcessor:
        return NmapResultProcessor(self.logger)

    def get_scan_by_id(self, scan_id: int) -> Optional[NmapScan]:
        """
        Retrieve an NmapScan by its primary key with relationships eagerly loaded.

        Args:
            scan_id: Primary key of the scan.

        Returns:
            NmapScan instance with open_ports_relation and port loaded, or None.
        """
        with UnitOfWork() as uow:
            scan = ScanRepository(uow).get_nmap_rich(scan_id)

        if scan:
            self.logger.info(f"Escaneo Nmap {scan_id} encontrado")
        else:
            self.logger.warning(f"Escaneo Nmap {scan_id} no encontrado")

        return scan

    def get_scans_for_user(self) -> List[NmapScan]:
        """
        Retrieve all NmapScans for the active user with relationships eagerly loaded.

        Returns:
            List of NmapScan instances.
        """
        with UnitOfWork() as uow:
            scans = ScanRepository(uow).get_nmap_by_user(self.active_user.id)

        self.logger.info(f"Se obtuvieron {len(scans)} escaneos Nmap")
        return scans

    def generate_report(self, scan_id: int, ai_report: bool = False) -> int:
        """
        Create a SentinelDocument and start async PDF generation for an Nmap scan.

        Args:
            scan_id:   Primary key of the scan.
            ai_report: Include AI-generated analysis in the report.

        Returns:
            Primary key of the created SentinelDocument.
        """
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            raise ValueError(f"Escaneo {scan_id} no encontrado")

        self.logger.info(f"Creando documento con ai_report: {ai_report}")

        with UnitOfWork() as uow:
            doc_repo = SentinelDocumentRepository(uow)
            document = SentinelDocument(
                scan_id       = scan.id,
                scan_type     = scan.scan_type,
                document_type = "sentinel",
                filename      = "",
                format        = "pdf",
                status        = "running",
                user_id       = scan.user_id,
                is_ai_generated = 1 if ai_report else 0,
            )
            doc_repo.save(document)
            doc_id = document.id
            # commits on __exit__

        thread = threading.Thread(
            target = self._generate_pdf_async,
            args   = (doc_id, scan.id, ai_report),
            daemon = True,
            name   = f"PDFGeneration-Scan-{scan.id}",
        )
        thread.start()
        return doc_id

    def _generate_pdf_async(self, document_id: int, scan_id: int, ai_report: bool = False) -> None:
        """Generate PDF in a background thread and update the document status."""
        thread_manager = self.__class__(self.active_user)
        document = None

        try:
            document = thread_manager.get_document_by_id(document_id)
            if not document:
                thread_manager.logger.error(f"Documento {document_id} no encontrado para generación de PDF")
                return

            scan = thread_manager.get_scan_by_id(scan_id)
            if not scan or scan.scan_type != "nmap":
                thread_manager.logger.error(
                    f"Escaneo {scan_id} no válido para NmapScanManager "
                    f"(tipo: {getattr(scan, 'scan_type', 'N/A')})"
                )
                return

            strategy  = NmapPrintingStrategy(scan)
            pdf_path  = PDFCreator(strategy).print_pdf(ai_report=ai_report)

            with UnitOfWork() as uow:
                doc = SentinelDocumentRepository(uow).get_by_id(document_id)
                if doc:
                    doc.filename     = pdf_path
                    doc.status       = "done"
                    doc.generated_at = datetime.utcnow()

            thread_manager.logger.info(f"PDF generado exitosamente para documento {document_id}")

        except Exception as e:
            thread_manager.logger.error(f"Error generando PDF para documento {document_id}: {e}", exc_info=True)
            try:
                with UnitOfWork() as uow:
                    doc = SentinelDocumentRepository(uow).get_by_id(document_id)
                    if doc:
                        doc.status = "error"
            except Exception:
                pass

    def _extract_domain_data(self, processor, task, scan):
        return processor.process(task.results, scan.target)

    def _persist_scan_results(self, session, scan, domain_data) -> None:
        """Persist Nmap host and port data into the database."""
        host_data, ports_data = domain_data

        host = self._get_or_create_host_in_session(
            session,
            hostname    = host_data["hostname"],
            ip_address  = host_data["ip_address"],
            mac_address = host_data["mac_address"],
            vendor      = host_data["vendor"],
        )
        scan.host_id = host.id

        for port_info in ports_data:
            port = self._obtain_or_create_port(session, port_info["protocol"])
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
            session.add(open_port)

    def _obtain_or_create_port(self, session, protocol: str):
        """Get or create a Port row by its protocol string."""
        from src.modules.sentinel import Port

        port = session.query(Port).filter(Port.protocol == protocol).one_or_none()
        if port:
            return port

        new_port = Port(protocol=protocol)
        session.add(new_port)
        session.flush()
        return new_port


# =============================================================================
# NIKTO
# =============================================================================

class NiktoScanManager(ScanManager):
    """
    Manager for Nikto web vulnerability scans.

    Example:
        >>> manager = NiktoScanManager(user)
        >>> scan_id = manager.run_scan(target_domain="example.com")
    """

    def run_scan(self, target_domain: str, timeout: int = 60) -> int:
        """
        Start a Nikto scan in a background thread.

        Args:
            target_domain: Target domain or hostname.
            timeout:       Maximum scan duration in seconds.

        Returns:
            Primary key of the created NiktoScan record.
        """
        try:
            scan    = self._create_scan_record(target=target_domain)
            scan_id = scan.id

            task = NiktoScanTask(target_domain=target_domain, timeout=timeout)

            thread = threading.Thread(
                target = self._execute_scan_in_thread,
                args   = (scan_id, task),
                daemon = True,
                name   = f"NiktoScan-{scan_id}",
            )

            self._register_task(scan_id, task, thread)
            thread.start()

            self.logger.info(f"Escaneo Nikto {scan_id} iniciado")
            return scan_id

        except Exception as e:
            self.logger.error(f"Error iniciando escaneo Nikto: {e}", exc_info=True)
            raise

    def _create_scan_record(self, target: str) -> NiktoScan:
        """Create and persist a NiktoScan row."""
        scan = NiktoScan(target=target, user_id=self.active_user.id, started_at=datetime.now())
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
        return scan

    def _get_result_processor(self) -> NiktoResultProcessor:
        return NiktoResultProcessor(self.logger)

    def get_scan_by_id(self, scan_id: int) -> Optional[NiktoScan]:
        """
        Retrieve a NiktoScan by its primary key with incidents eagerly loaded.

        Args:
            scan_id: Primary key of the scan.

        Returns:
            NiktoScan instance with incidents loaded, or None.
        """
        with UnitOfWork() as uow:
            scan = ScanRepository(uow).get_nikto_rich(scan_id)

        if scan:
            self.logger.info(f"Escaneo Nikto {scan_id} encontrado")
        else:
            self.logger.warning(f"Escaneo Nikto {scan_id} no encontrado")

        return scan

    def get_scans_for_user(self) -> List[NiktoScan]:
        """
        Retrieve all NiktoScans for the active user with incidents eagerly loaded.

        Returns:
            List of NiktoScan instances.
        """
        with UnitOfWork() as uow:
            scans = ScanRepository(uow).get_nikto_by_user(self.active_user.id)

        self.logger.info(f"Se obtuvieron {len(scans)} escaneos Nikto")
        return scans

    def generate_report(self, scan_id: int, ai_report: bool = False) -> int:
        """
        Create a SentinelDocument and start async PDF generation for a Nikto scan.

        Returns:
            Primary key of the created SentinelDocument.
        """
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            raise ValueError(f"Escaneo {scan_id} no encontrado")

        with UnitOfWork() as uow:
            document = SentinelDocument(
                scan_id         = scan.id,
                scan_type       = scan.scan_type,
                document_type   = "sentinel",
                filename        = "",
                format          = "pdf",
                status          = "running",
                user_id         = scan.user_id,
                is_ai_generated = 1 if ai_report else 0,
            )
            SentinelDocumentRepository(uow).save(document)
            doc_id = document.id

        thread = threading.Thread(
            target = self._generate_pdf_async,
            args   = (doc_id, scan.id, ai_report),
            daemon = True,
            name   = f"PDFGeneration-Scan-{scan.id}",
        )
        thread.start()
        return doc_id

    def _generate_pdf_async(self, document_id: int, scan_id: int, ai_report: bool = False) -> None:
        """Generate PDF in a background thread and update the document status."""
        thread_manager = self.__class__(self.active_user)
        document = None

        try:
            document = thread_manager.get_document_by_id(document_id)
            if not document:
                thread_manager.logger.error(f"Documento {document_id} no encontrado")
                return

            scan = thread_manager.get_scan_by_id(scan_id)
            if not scan or scan.scan_type != "nikto":
                thread_manager.logger.error(f"Escaneo {scan_id} no válido para NiktoScanManager")
                return

            strategy = NiktoPrintingStrategy(scan)
            pdf_path = PDFCreator(strategy).print_pdf(ai_report=ai_report)

            with UnitOfWork() as uow:
                doc_repo = SentinelDocumentRepository(uow)
                doc = doc_repo.get_by_id(document_id)
                if doc:
                    doc.filename     = pdf_path
                    doc.status       = "done"
                    doc.generated_at = datetime.utcnow()

            thread_manager.logger.info(f"PDF generado exitosamente para documento {document_id}")

        except Exception as e:
            thread_manager.logger.error(f"Error generando PDF para documento {document_id}: {e}", exc_info=True)
            try:
                with UnitOfWork() as uow:
                    doc = SentinelDocumentRepository(uow).get_by_id(document_id)
                    if doc:
                        doc.status = "error"
            except Exception:
                pass

    def _extract_domain_data(self, processor, task, scan):
        return processor.process(task.results)

    def _persist_scan_results(self, session, scan, domain_data) -> None:
        """Persist Nikto incidents and associate a host."""
        incidents_data = domain_data

        for inc_data in incidents_data:
            incident = self._obtain_or_create_incident(session, inc_data)
            if incident not in scan.incidents:
                scan.incidents.append(incident)

        host = self._get_or_create_host_for_nikto(
            session,
            hostname   = scan.target,
            ip_address = scan.target,
        )
        scan.host = host

    def _obtain_or_create_incident(self, session, inc_data: dict) -> NiktoIncident:
        """Get or create a NiktoIncident row by its unique fields."""
        existing = session.query(NiktoIncident).filter(
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
        session.add(incident)
        session.flush()
        return incident


# =============================================================================
# OPENVAS
# =============================================================================

class OpenVASScanManager(ScanManager):
    """
    Manager for OpenVAS vulnerability scans.

    Reads OpenVAS connection parameters from the configuration module on init.

    Class Attributes:
        SCAN_CONFIGS: Known scan configuration UUIDs.
        PORT_LISTS:   Known port list UUIDs.

    Example:
        >>> manager = OpenVASScanManager(user)
        >>> scan_id = manager.run_scan(target="192.168.1.1")
    """

    SCAN_CONFIGS = {
        "full_fast":     "daba56c8-73ec-11df-a475-002264764cea",
        "full_deep":     "8715c877-47a0-438d-98a3-27c7a6ab2196",
        "full_ultimate": "085569ce-73ed-11df-83c3-002264764cea",
    }

    PORT_LISTS = {
        "tcp_all":           "33d0cd82-57c6-11e1-8ed1-406186ea4fc5",
        "tcp_udp_all":       "4a4717fe-57d2-11e1-9a26-406186ea4fc5",
        "tcp_all_udp_top100":"730ef368-57e2-11e1-a90f-406186ea4fc5",
    }

    def __init__(self, user: User) -> None:
        super().__init__(user)

        config         = CR.get_openvas_config()
        self.hostname  = config["hostname"]
        self.port      = config["port"]
        self.username  = config["username"]
        self.password  = config["password"]

    def run_scan(self, target: str, scan_config: str = "full_fast", skip_normalize: bool = False) -> int:
        """
        Start an OpenVAS scan in a background thread.

        Args:
            target:         Target IP address or hostname.
            scan_config:    Scan configuration key (default: 'full_fast').
            skip_normalize: Skip target normalization if True.

        Returns:
            Primary key of the created OpenVASScan record.
        """
        try:
            config_id = self.SCAN_CONFIGS.get(scan_config, self.SCAN_CONFIGS["full_fast"])
            scan      = self._create_scan_record(target=target)
            scan_id   = scan.id

            task = OpenVASTask(
                target      = target,
                hostname    = self.hostname,
                port        = self.port,
                username    = self.username,
                password    = self.password,
                scan_config = config_id,
            )

            thread = threading.Thread(
                target = self._execute_scan_in_thread,
                args   = (scan_id, task, skip_normalize),
                daemon = True,
                name   = f"OpenVASScan-{scan_id}",
            )

            self._register_task(scan_id, task, thread)
            thread.start()

            self.logger.info(f"Escaneo OpenVAS {scan_id} iniciado")
            return scan_id

        except Exception as e:
            self.logger.error(f"Error iniciando escaneo OpenVAS: {e}", exc_info=True)
            raise

    def _create_scan_record(self, target: str) -> OpenVASScan:
        """Create and persist an OpenVASScan row with placeholder task/report IDs."""
        placeholder = f"PENDING_{uuid.uuid4()}"
        scan = OpenVASScan(
            target    = target,
            user_id   = self.active_user.id,
            task_id   = placeholder,
            report_id = placeholder,
        )
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
        return scan

    def _get_result_processor(self) -> OpenVASResultProcessor:
        return OpenVASResultProcessor(self.logger)

    def get_scan_by_id(self, scan_id: int) -> Optional[OpenVASScan]:
        """
        Retrieve an OpenVASScan by its primary key with relationships eagerly loaded.

        Args:
            scan_id: Primary key of the scan.

        Returns:
            OpenVASScan instance with results, vulnerabilities and hosts loaded, or None.
        """
        with UnitOfWork() as uow:
            scan = ScanRepository(uow).get_openvas_rich(scan_id)

        if scan:
            self.logger.info(f"Escaneo OpenVAS {scan_id} encontrado")
        else:
            self.logger.warning(f"Escaneo OpenVAS {scan_id} no encontrado")

        return scan

    def get_scans_for_user(self) -> List[OpenVASScan]:
        """
        Retrieve all OpenVASScans for the active user with relationships eagerly loaded.

        Returns:
            List of OpenVASScan instances.
        """
        with UnitOfWork() as uow:
            scans = ScanRepository(uow).get_openvas_by_user(self.active_user.id)

        self.logger.info(f"Se obtuvieron {len(scans)} escaneos OpenVAS")
        return scans

    def _execute_scan_in_thread(self, scan_id: int, task: OpenVASTask, skip_normalize: bool = False) -> None:
        """
        Override: after the base execution, persist the OpenVAS task/report IDs.

        Args:
            scan_id:        Primary key of the scan.
            task:           OpenVASTask instance.
            skip_normalize: Skip IP normalization if True.
        """
        if not skip_normalize:
            target_ip, _ = normalize_target(task.target)
            task.target  = target_ip

        super()._execute_scan_in_thread(scan_id, task)

        if task.task_id:
            try:
                with UnitOfWork() as uow:
                    scan = ScanRepository(uow).get_by_id(scan_id)
                    if scan:
                        scan.task_id   = task.task_id
                        scan.report_id = task.report_id
            except Exception as e:
                self.logger.error(f"Error actualizando task_id/report_id para escaneo {scan_id}: {e}")

    def generate_report(self, scan_id: int, ai_report: bool = False) -> int:
        """
        Create a SentinelDocument and start async PDF generation for an OpenVAS scan.

        Returns:
            Primary key of the created SentinelDocument.
        """
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            raise ValueError(f"Escaneo {scan_id} no encontrado")

        with UnitOfWork() as uow:
            document = SentinelDocument(
                scan_id         = scan.id,
                scan_type       = scan.scan_type,
                document_type   = "sentinel",
                filename        = "",
                format          = "pdf",
                status          = "running",
                user_id         = scan.user_id,
                is_ai_generated = 1 if ai_report else 0,
            )
            SentinelDocumentRepository(uow).save(document)
            doc_id = document.id

        thread = threading.Thread(
            target = self._generate_pdf_async,
            args   = (doc_id, scan.id, ai_report),
            daemon = True,
            name   = f"PDFGeneration-Scan-{scan.id}",
        )
        thread.start()
        return doc_id

    def _generate_pdf_async(self, document_id: int, scan_id: int, ai_report: bool = False) -> None:
        """Generate PDF in a background thread and update the document status."""
        thread_manager = self.__class__(self.active_user)

        try:
            document = thread_manager.get_document_by_id(document_id)
            if not document:
                thread_manager.logger.error(f"Documento {document_id} no encontrado")
                return

            scan = thread_manager.get_scan_by_id(scan_id)
            if not scan or scan.scan_type != "openvas":
                thread_manager.logger.error(f"Escaneo {scan_id} no válido para OpenVASScanManager")
                return

            strategy = OpenVASPrintingStrategy(scan)
            pdf_path = PDFCreator(strategy).print_pdf(ai_report=ai_report)

            with UnitOfWork() as uow:
                doc = SentinelDocumentRepository(uow).get_by_id(document_id)
                if doc:
                    doc.filename     = pdf_path
                    doc.status       = "done"
                    doc.generated_at = datetime.utcnow()

            thread_manager.logger.info(f"PDF generado exitosamente para documento {document_id}")

        except Exception as e:
            thread_manager.logger.error(f"Error generando PDF para documento {document_id}: {e}", exc_info=True)
            try:
                with UnitOfWork() as uow:
                    doc = SentinelDocumentRepository(uow).get_by_id(document_id)
                    if doc:
                        doc.status = "error"
            except Exception:
                pass

    def _extract_domain_data(self, processor, task, scan):
        return processor.process(task.results)

    def _persist_scan_results(self, session, scan, domain_data) -> None:
        """Persist OpenVAS vulnerabilities, hosts, and scan results."""
        vulnerabilities_data, scan_results_data, _ = domain_data

        vulnerability_map = {}
        for vuln_data in vulnerabilities_data:
            vuln = self._obtain_or_create_vulnerability(session, vuln_data)
            vulnerability_map[vuln.nvt_oid] = vuln

        for result_data in scan_results_data:
            host = self._get_or_create_host_in_session(
                session,
                hostname   = result_data["host_ip"],
                ip_address = result_data["host_ip"],
            )

            scan_result = OpenVASScanResult(
                openvas_scan_id  = scan.id,
                vulnerability_id = vulnerability_map[result_data["nvt_oid"]].id,
                host_id          = host.id,
            )
            session.add(scan_result)

        session.flush()

    def _obtain_or_create_vulnerability(self, session, vuln_data: dict):
        """Get or create an OpenVASVulnerability row by NVT OID."""
        from src.modules.sentinel import OpenVASVulnerability

        nvt_oid = vuln_data["nvt_oid"]
        vuln = session.query(OpenVASVulnerability).filter(
            OpenVASVulnerability.nvt_oid == nvt_oid
        ).one_or_none()

        if vuln:
            return vuln

        vuln = OpenVASVulnerability(**vuln_data)
        session.add(vuln)
        session.flush()
        return vuln