"""
Managers for security scan orchestration and result persistence.

This module provides manager classes for coordinating various security scans:
- NmapScanManager: Network exploration and security scanning
- NiktoScanManager: Web server vulnerability scanning
- OpenVASScanManager: Comprehensive vulnerability management

Each manager handles the complete lifecycle of a scan including:
- Creating scan records in the database
- Executing scans in background threads
- Processing and saving results
- Generating PDF reports

Usage:
    manager = NmapScanManager(user)
    scan_id = manager.run_scan(target_host="192.168.1.1", target_ports="1-1000")
    scan = manager.get_scan_by_id(scan_id)
"""

import threading
import uuid
from enum import Enum
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy.orm import Session, joinedload

from src.core.model import (
    NiktoScan,
    NmapScan,
    OpenPort,
    OpenVASScan,
    OpenVASScanResult,
    Scan,
    ScanStatus,
    User,
    SentinelDocument
)
from src.logic.processors import (
    NiktoResultProcessor,
    NmapResultProcessor,
    OpenVASResultProcessor,
    ScanResultProcessor,
)
from src.logic.documents import PDFCreator, NmapPrintingStrategy, NiktoPrintingStrategy, OpenVASPrintingStrategy

from src.logic.tasks import NiktoScanTask, NmapScanTask, OpenVASTask, TaskStatus, _Task
from src.misc import ConfigReader, normalize_target

from ._base import BaseManager


class ScanManager(BaseManager, ABC):
    """Base class for scan managers.

    Responsibilities:
        - Coordinate task execution and result persistence
        - Manage scan lifecycle (create, execute, cancel, delete)
        - Track running tasks and threads
        - Provide common scan operations

    Class Attributes:
        _running_tasks: Dictionary mapping scan_id to running task.
        _running_threads: Dictionary mapping scan_id to running thread.
        _running_tasks_lock: RLock for thread-safe task management.

    Attributes:
        active_user: User executing the scan operations.
    """

    _running_tasks: Dict[int, _Task] = {}
    _running_threads: Dict[int, threading.Thread] = {}
    _running_tasks_lock = threading.RLock()

    def __init__(self, user: User, session: Optional[Session] = None):
        """Initialize the scan manager.

        Args:
            user: User performing the scan operations.
            session: Optional database session.
        """
        super().__init__(session)
        self.active_user = user

    @classmethod
    def _register_task(cls, scan_id: int, task: _Task, thread: Optional[threading.Thread] = None) -> None:
        """Register a running task and its thread.

        Args:
            scan_id: ID of the scan.
            task: Task instance to register.
            thread: Thread running the task.
        """
        with cls._running_tasks_lock:
            cls._running_tasks[scan_id] = task
            if thread is not None:
                cls._running_threads[scan_id] = thread

    @classmethod
    def _get_task(cls, scan_id: int) -> Optional[_Task]:
        """Get a registered task by scan ID.

        Args:
            scan_id: ID of the scan.

        Returns:
            Task instance or None if not found.
        """
        with cls._running_tasks_lock:
            return cls._running_tasks.get(scan_id)

    @classmethod
    def _unregister_task(cls, scan_id: int) -> None:
        """Unregister a task and its thread.

        Args:
            scan_id: ID of the scan to unregister.
        """
        with cls._running_tasks_lock:
            cls._running_tasks.pop(scan_id, None)
            cls._running_threads.pop(scan_id, None)

    @classmethod
    def cancel_all_running(cls, timeout: float = 10.0) -> None:
        """Cancel all running tasks and wait for threads to finish.

        Intended to be called from the shutdown signal handler.

        Args:
            timeout: Maximum time to wait for threads to join.
        """
        with cls._running_tasks_lock:
            task_snapshot = dict(cls._running_tasks)
            thread_snapshot = dict(cls._running_threads)

        for scan_id, task in task_snapshot.items():
            try:
                task.cancel()
            except Exception:
                pass

        for scan_id, thread in thread_snapshot.items():
            thread.join(timeout=timeout)

    def get_scan_by_id(self, scan_id: int) -> Optional[Scan]:
        """Get a scan by its ID.

        Args:
            scan_id: ID of the scan to retrieve.

        Returns:
            Scan instance or None if not found.
        """
        try:
            self._check_session()
            scan = self.session.query(Scan).filter(Scan.id == scan_id).one_or_none()

            if scan:
                self.logger.info(f"Escaneo {scan_id} encontrado")
            else:
                self.logger.warning(f"Escaneo {scan_id} no encontrado")

            return scan

        except Exception as e:
            self.logger.error(f"Error obteniendo escaneo {scan_id}: {e}", exc_info=True)
            raise

    def get_scans_for_user(self) -> List[Scan]:
        """Get all scans for the active user.

        Returns:
            List of Scan instances.
        """
        try:
            self._check_session()
            scans = self.session.query(Scan).filter(
                Scan.user_id == self.active_user.id
            ).all()

            self.logger.info(f"Se obtuvieron {len(scans)} escaneos")
            return scans

        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error obteniendo escaneos: {e}", exc_info=True)
            raise

    def delete_scan(self, scan_id: int) -> bool:
        """Delete a scan and its associated documents.

        Args:
            scan_id: ID of the scan to delete.

        Returns:
            True if deleted successfully, False otherwise.
        """
        try:
            self._check_session()
            scan = self.get_scan_by_id(scan_id)

            if not scan:
                return False

            from src.core.model import SentinelDocument
            docs = self.session.query(SentinelDocument).filter(
                SentinelDocument.scan_id == scan_id
            ).all()
            for doc in docs:
                self.session.delete(doc)
            
            self.session.delete(scan)
            self._safe_commit()

            self.logger.info(f"Escaneo {scan_id} eliminado")
            return True

        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error eliminando escaneo {scan_id}: {e}")
            raise

    def get_scan_progress(self, scan_id: int) -> Optional[int]:
        """Get the progress percentage of a running scan.

        Args:
            scan_id: ID of the scan.

        Returns:
            Progress percentage (0-100) or None if not running.
        """
        task = self._get_task(scan_id)
        if task:
            progress = task.progress
            self.logger.debug(f"Progreso de escaneo {scan_id}: {progress}%")
            return progress
        return None

    def get_scan_status(self, scan_id: int) -> Optional[str]:
        """Get the status of a scan.

        Args:
            scan_id: ID of the scan.

        Returns:
            Status string or None if not found.
        """
        task = self._get_task(scan_id)
        if task:
            return str(task.status)
        if self.is_scan_finished(scan_id):
            return str(TaskStatus.COMPLETED)
        return None

    def get_document_by_id(self, document_id: int):
        """Get a document by its ID.

        Args:
            document_id: ID of the document to retrieve.

        Returns:
            SentinelDocument instance or None if not found.
        """
        try:
            self._check_session()
            document = self.session.query(SentinelDocument).filter(
                SentinelDocument.id == document_id
            ).one_or_none()

            if document:
                self.logger.info(f"Documento {document_id} encontrado")
            else:
                self.logger.warning(f"Documento {document_id} no encontrado")

            return document

        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error obteniendo documento {document_id}: {e}", exc_info=True)
            raise

    def is_scan_finished(self, scan_id: int) -> Optional[bool]:
        """Check if a scan has finished.

        Args:
            scan_id: ID of the scan to check.

        Returns:
            True if finished, False otherwise.
        """
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            self.logger.warning(f"Escaneo {scan_id} no encontrado para verificar finalización")
            return False

        is_finished = scan.status == ScanStatus.FINISHED.value
        return is_finished

    def cancel_scan(self, scan_id: int) -> bool:
        """Cancel a running scan.

        Args:
            scan_id: ID of the scan to cancel.

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
                    f"El usuario {self.active_user.username} no tiene permisos para cancelar el escaneo {scan_id}"
                )
                return False

            if scan.status not in ['pending', 'running']:
                self.logger.warning(
                    f"El escaneo {scan_id} no se puede cancelar (estado actual: {scan.status})"
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

            self._mark_scan_as(scan, ScanStatus.CANCELLED)
            self._safe_commit()

            self.logger.info(f"Escaneo {scan_id} cancelado exitosamente")
            return True

        except Exception as e:
            self.logger.error(f"Error cancelando escaneo {scan_id}: {e}", exc_info=True)
            return False

    @abstractmethod
    def run_scan(self, **kwargs) -> int:
        """Start a new scan.

        Returns:
            Scan ID of the created scan.
        """
        pass

    @abstractmethod
    def _create_scan_record(self, **kwargs) -> Scan:
        """Create a new scan record in the database.

        Returns:
            Created scan record.
        """
        pass

    @abstractmethod
    def _get_result_processor(self) -> ScanResultProcessor:
        """Get the result processor for this scan type.

        Returns:
            Result processor instance.
        """
        pass

    @abstractmethod
    def generate_report(self, scan_id: int) -> bytes:
        """Generate a PDF report for the scan.

        Args:
            scan_id: ID of the scan to generate report for.

        Returns:
            Report bytes.
        """
        pass

    def _execute_scan_in_thread(self, scan_id: int, task: _Task) -> None:
        """Ejecuta escaneo en hilo background y persiste resultados."""
        thread_manager = self.__class__(self.active_user)

        try:
            scan = thread_manager.get_scan_by_id(scan_id)
            if not scan:
                thread_manager.logger.error(f"Escaneo {scan_id} no encontrado")
                return

            thread_manager.logger.info(f"Iniciando escaneo {scan_id}")

            TIME_MARGIN = 30
            task.scan()
            success = task.wait(timeout=task.timeout + TIME_MARGIN)
            has_no_results = task.results is None

            if not success or has_no_results:
                thread_manager.logger.error(f"Escaneo {scan_id} falló. Estado: {task.status}")
                thread_manager._mark_scan_as(scan, ScanStatus.FAILED)
                return

            thread_manager.logger.info(f"Procesando resultados de escaneo {scan_id}")
            
            processor = thread_manager._get_result_processor()
            domain_data = thread_manager._extract_domain_data(processor, task, scan)
            thread_manager._persist_scan_results(scan, domain_data)
            
            thread_manager._mark_scan_as(scan, ScanStatus.FINISHED)
            thread_manager._safe_commit()

            thread_manager.logger.info(f"Escaneo {scan_id} completado exitosamente")

        except Exception as e:
            thread_manager.logger.error(f"Error en escaneo {scan_id}: {e}", exc_info=True)
            try:
                thread_manager._safe_rollback()
                error_scan = thread_manager.get_scan_by_id(scan_id)
                if error_scan:
                    thread_manager._mark_scan_as(error_scan, ScanStatus.FAILED)
                    thread_manager._safe_commit()
            except Exception as update_err:
                thread_manager.logger.error(f"Error actualizando estado: {update_err}")
        finally:
            thread_manager.close_session()
            self._unregister_task(scan_id)

    def _mark_scan_as(self, scan: Scan, status: ScanStatus) -> None:
        """Update scan status and finished timestamp.

        Args:
            scan: Scan instance to update.
            status: New status to set.
        """
        old_status = scan.status
        scan.status = status.value
        scan.finished_at = datetime.now()
        self.logger.info(f"Estado del escaneo {scan.id} actualizado: {old_status} -> {status.value}")
    
    def _get_or_create_host(self, hostname: str, ip_address: str):
        """Versión simplificada para Nikto."""
        from src.core.model import Host
        from src.misc import normalize_target
        
        # Normalizar si es necesario
        ip, host = normalize_target(hostname, resolve_hostname=True)
        final_hostname = host or ip or hostname
        final_ip = ip or ip_address
        
        host_obj = self.session.query(Host).filter(Host.hostname == final_hostname).first()
        if host_obj:
            return host_obj
        
        host_obj = Host(hostname=final_hostname, ip_address=final_ip, mac_address="")
        self.session.add(host_obj)
        self.session.flush()
        return host_obj

    @abstractmethod
    def _extract_domain_data(self, processor, task, scan):
        """Extrae datos de dominio del processor."""
        pass
    
    @abstractmethod
    def _persist_scan_results(self, scan, domain_data):
        """Persiste los datos procesados en la base de datos."""
        pass   


class NmapScanManager(ScanManager):
    """Manager for Nmap network security scans.

    Handles Nmap scan execution, result processing, and PDF report generation.
    Inherits from ScanManager to provide common scan operations.

    Attributes:
        scan_type: Type identifier for this manager ('nmap').

    Example:
        >>> manager = NmapScanManager(user)
        >>> scan_id = manager.run_scan(target_host="192.168.1.1", target_ports="1-1000")
    """

    def run_scan(self, target_host: str, target_ports: str, timeout: int = 300) -> int:
        """Start an Nmap scan.

        Args:
            target_host: Target IP address or hostname.
            target_ports: Port range to scan (e.g., "1-1000").
            timeout: Maximum scan duration in seconds.

        Returns:
            Scan ID of the created scan record.
        """
        try:
            scan = self._create_scan_record(target=target_host)
            scan_id = scan.id

            task = NmapScanTask(
                target_host=target_host,
                target_ports=target_ports,
                timeout=timeout
            )

            thread = threading.Thread(
                target=self._execute_scan_in_thread,
                args=(scan_id, task),
                daemon=True,
                name=f"NmapScan-{scan_id}"
            )

            self._register_task(scan_id, task, thread)
            thread.start()

            self.logger.info(f"Escaneo Nmap {scan_id} iniciado")
            return scan_id

        except Exception as e:
            self.logger.error(f"Error iniciando escaneo Nmap: {e}", exc_info=True)
            raise

    def _create_scan_record(self, target: str) -> NmapScan:
        """Create an NmapScan record in the database.

        Args:
            target: Target host or IP address.

        Returns:
            Created NmapScan instance.
        """
        scan = NmapScan(
            target=target,
            user=self.active_user,
            started_at=datetime.now()
        )
        self.session.add(scan)
        self._safe_commit()
        return scan

    def _get_result_processor(self) -> NmapResultProcessor:
        """Get the Nmap result processor.

        Returns:
            NmapResultProcessor instance.
        """
        return NmapResultProcessor(self.logger)

    def get_scans_for_user(self) -> List[NmapScan]:
        """Get all Nmap scans for the active user.

        Returns:
            List of NmapScan instances with loaded relationships.
        """
        try:
            self._check_session()
            scans = (
                self.session.query(NmapScan)
                .filter(NmapScan.user_id == self.active_user.id)
                .options(
                    joinedload(NmapScan.open_ports_relation).joinedload(OpenPort.port),
                )
                .all()
            )
            self.logger.info(f"Se obtuvieron {len(scans)} escaneos Nmap")
            return scans
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error obteniendo escaneos Nmap: {e}", exc_info=True)
            raise

    def generate_report(self, scan_id: int, ai_report: bool = False) -> int:
        """Generate a PDF report for an Nmap scan.

        Args:
            scan_id: ID of the scan.
            ai_report: Include AI-generated analysis in the report.

        Returns:
            Document ID of the generated document.
        """
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            self.logger.error(f"Escaneo {scan_id} no encontrado para generar reporte")
            raise ValueError(f"Escaneo {scan_id} no encontrado")

        document = SentinelDocument(
            scan_id=scan.id,
            scan_type=scan.scan_type,
            document_type="sentinel",
            filename="",
            format="pdf",
            status="pending",
            user_id=scan.user_id
        )
        
        self.session.add(document)
        self.session.flush()
        
        document.status = "running"
        self.session.commit()

        thread = threading.Thread(
            target=self._generate_pdf_async,
            args=(document.id, scan.id, ai_report),
            daemon=True,
            name=f"PDFGeneration-Scan-{scan.id}"
        )

        thread.start()
        return document.id

    def _generate_pdf_async(self, document_id: int, scan_id: int, ai_report: bool = False):
        """Generate PDF asynchronously in a background thread.

        Args:
            document_id: ID of the document to update.
            scan_id: ID of the source scan.
            ai_report: Include AI-generated analysis in the report.
        """
        thread_manager = self.__class__(self.active_user)
        document = None
        
        try:
            document = thread_manager.get_document_by_id(document_id)
            if not document:
                thread_manager.logger.error(f"Documento {document_id} no encontrado para generación de PDF")
                return

            scan = thread_manager.get_scan_by_id(scan_id)
            if not scan:
                thread_manager.logger.error(f"Escaneo {scan_id} no encontrado para generación de PDF")
                return

            scan_type = scan.scan_type
            if scan_type != "nmap":
                thread_manager.logger.error(f"Tipo de escaneo {scan_type} no soportado para generación de PDF a traves de NmapScanManager")
                return

            thread_manager.logger.info(f"Generando análisis de seguridad con IA para el informe del escaneo {scan_id}")
            
            strategy = NmapPrintingStrategy(scan)
            pdf_creator = PDFCreator(strategy)
            pdf_path = pdf_creator.print_pdf(ai_report=ai_report)

            document.filename = pdf_path
            document.status = "done"
            document.generated_at = datetime.utcnow()
            thread_manager._safe_commit()
            
            thread_manager.logger.info(f"PDF generado exitosamente para documento {document_id}")

        except Exception as e:
            thread_manager.logger.error(f"Error generando PDF para documento {document_id}: {e}", exc_info=True)
            if document:
                document.status = "error"
                thread_manager._safe_commit()
        
        finally:
            thread_manager.close_session()

    def _extract_domain_data(self, processor, task, scan):
        """Extrae datos de hosts y puertos."""
        return processor.process(task.results, scan.target)

    def _persist_scan_results(self, scan, domain_data):
        """Persiste resultados Nmap."""
        host_data, ports_data = domain_data
        
        # Persistir host
        host = self._get_or_create_host(
            hostname=host_data['hostname'],
            ip_address=host_data['ip_address'],
            mac_address=host_data['mac_address'],
            vendor=host_data['vendor']
        )
        scan.host_id = host.id
        
        # Persistir puertos
        for port_info in ports_data:
            port = self._obtain_or_create_port(port_info['protocol'])
            if port not in scan.target_ports:
                scan.target_ports.append(port)
            
            open_port = OpenPort(
                nmap_scan_id=scan.id,
                port_id=port.id,
                reason=port_info['reason'],
                product=port_info['product'],
                version=port_info['version'],
                given_use=port_info['given_use']
            )
            self.session.add(open_port)

    def _obtain_or_create_port(self, protocol: str):
        """Obtiene o crea un puerto por su protocolo."""
        from src.core.model import Port
        port = self.session.query(Port).filter(Port.protocol == protocol).one_or_none()
        if port:
            return port
        
        new_port = Port(protocol=protocol)
        self.session.add(new_port)
        self.session.flush()
        return new_port
    
    def _get_or_create_host(self, hostname: str, ip_address: str, mac_address: str = "", vendor: str = ""):
        """Obtiene o crea un host."""
        from src.core.model import Host
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        
        host = self.session.query(Host).filter(Host.hostname == hostname).first()
        if host:
            return host
        
        stmt = pg_insert(Host).values(
            hostname=hostname,
            ip_address=ip_address,
            mac_address=mac_address or "",
            vendor=vendor
        ).on_conflict_do_nothing(index_elements=["hostname"])
        
        self.session.execute(stmt)
        self.session.flush()
        
        return self.session.query(Host).filter(Host.hostname == hostname).first()


class NiktoScanManager(ScanManager):
    """Manager for Nikto web vulnerability scans.

    Handles Nikto scan execution, result processing, and PDF report generation.
    Inherits from ScanManager to provide common scan operations.

    Attributes:
        scan_type: Type identifier for this manager ('nikto').

    Example:
        >>> manager = NiktoScanManager(user)
        >>> scan_id = manager.run_scan(target_domain="example.com")
    """

    def run_scan(self, target_domain: str, timeout: int = 60) -> int:
        """Start a Nikto scan.

        Args:
            target_domain: Target domain or hostname.
            timeout: Maximum scan duration in seconds.

        Returns:
            Scan ID of the created scan record.
        """
        try:
            scan = self._create_scan_record(target=target_domain)
            scan_id = scan.id

            task = NiktoScanTask(
                target_domain=target_domain, 
                timeout=timeout
            )

            thread = threading.Thread(
                target=self._execute_scan_in_thread,
                args=(scan_id, task),
                daemon=True,
                name=f"NiktoScan-{scan_id}"
            )

            self._register_task(scan_id, task, thread)
            thread.start()

            self.logger.info(f"Escaneo Nikto {scan_id} iniciado")
            return scan_id

        except Exception as e:
            self.logger.error(f"Error iniciando escaneo Nikto: {e}", exc_info=True)
            raise

    def _create_scan_record(self, target: str) -> NiktoScan:
        """Create a NiktoScan record in the database.

        Args:
            target: Target domain.

        Returns:
            Created NiktoScan instance.
        """
        scan = NiktoScan(
            target=target,
            user=self.active_user,
            started_at=datetime.now()
        )
        self.session.add(scan)
        self._safe_commit()
        return scan

    def _get_result_processor(self) -> NiktoResultProcessor:
        """Get the Nikto result processor.

        Returns:
            NiktoResultProcessor instance.
        """
        return NiktoResultProcessor(self.logger)

    def get_scans_for_user(self) -> List[NiktoScan]:
        """Get all Nikto scans for the active user.

        Returns:
            List of NiktoScan instances with loaded relationships.
        """
        try:
            self._check_session()
            scans = (
                self.session.query(NiktoScan)
                .filter(NiktoScan.user_id == self.active_user.id)
                .options(
                    joinedload(NiktoScan.incidents),
                )
                .all()
            )
            self.logger.info(f"Se obtuvoeron {len(scans)} escaneos Nikto")
            return scans
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error obteniendo escaneos Nikto: {e}", exc_info=True)
            raise

    def generate_report(self, scan_id: int, ai_report: bool = False) -> int:
        """Generate a PDF report for a Nikto scan.

        Args:
            scan_id: ID of the scan.
            ai_report: Include AI-generated analysis in the report.

        Returns:
            Document ID of the generated document.
        """
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            self.logger.error(f"Escaneo {scan_id} no encontrado para generar reporte")
            raise ValueError(f"Escaneo {scan_id} no encontrado")

        document = SentinelDocument(
            scan_id=scan.id,
            scan_type=scan.scan_type,
            document_type="sentinel",
            filename="",
            format="pdf",
            status="pending",
            user_id=scan.user_id
        )
        
        self.session.add(document)
        self.session.flush()
        
        document.status = "running"
        self.session.commit()

        thread = threading.Thread(
            target=self._generate_pdf_async,
            args=(document.id, scan.id, ai_report),
            daemon=True,
            name=f"PDFGeneration-Scan-{scan.id}"
        )

        thread.start()
        return document.id

    def _generate_pdf_async(self, document_id: int, scan_id: int, ai_report: bool = False):
        """Generate PDF asynchronously in a background thread.

        Args:
            document_id: ID of the document to update.
            scan_id: ID of the source scan.
            ai_report: Include AI-generated analysis in the report.
        """
        thread_manager = self.__class__(self.active_user)
        document = None
        
        try:
            document = thread_manager.get_document_by_id(document_id)
            if not document:
                thread_manager.logger.error(f"Documento {document_id} no encontrado para generación de PDF")
                return

            scan = thread_manager.get_scan_by_id(scan_id)
            if not scan:
                thread_manager.logger.error(f"Escaneo {scan_id} no encontrado para generación de PDF")
                return

            scan_type = scan.scan_type
            if scan_type != "nikto":
                thread_manager.logger.error(f"Tipo de escaneo {scan_type} no soportado para generación de PDF para NiktoScanManager")
                return

            thread_manager.logger.info(f"Generando análisis de seguridad con IA para el informe del escaneo {scan_id}")
            
            strategy = NiktoPrintingStrategy(scan)
            pdf_creator = PDFCreator(strategy)
            pdf_path = pdf_creator.print_pdf(ai_report=ai_report)

            document.filename = pdf_path
            document.status = "done"
            document.generated_at = datetime.utcnow()
            thread_manager._safe_commit()
            
            thread_manager.logger.info(f"PDF generado exitosamente para documento {document_id}")

        except Exception as e:
            thread_manager.logger.error(f"Error generando PDF para documento {document_id}: {e}", exc_info=True)
            if document:
                document.status = "error"
                thread_manager._safe_commit()
        
        finally:
            thread_manager.close_session()

    def _extract_domain_data(self, processor, task, scan):
        return processor.process(task.results)

    def _persist_scan_results(self, scan, domain_data):
        """Persiste incidentes Nikto y asocia host."""
        from src.core.model import Host
        
        incidents_data = domain_data
        
        # Crear/obtener incidentes
        for inc_data in incidents_data:
            incident = self._obtain_or_create_incident(inc_data)
            if incident not in scan.incidents:
                scan.incidents.append(incident)
        
        # Asociar host (usando target del scan)
        host = self._get_or_create_host(
            hostname=scan.target,  # Nikto usa el target como hostname inicial
            ip_address=scan.target
        )
        scan.host = host
    
    def _obtain_or_create_incident(self, inc_data: dict):
        """Obtiene o crea un incidente Nikto."""
        from src.core.model import NiktoIncident
        
        existing = self.session.query(NiktoIncident).filter(
            NiktoIncident.description == inc_data['description'],
            NiktoIncident.url == inc_data['url'],
            NiktoIncident.method == inc_data['method'],
        ).first()
        
        if existing:
            return existing
        
        incident = NiktoIncident(
            description=inc_data['description'],
            osvdb_id=inc_data['osvdb_id'],
            method=inc_data['method'],
            url=inc_data['url'],
            severity=inc_data['severity']
        )
        self.session.add(incident)
        self.session.flush()
        return incident


class OpenVASScanManager(ScanManager):
    """Manager for OpenVAS vulnerability scans.

    Handles OpenVAS scan execution, result processing, and integration
    with the OpenVAS manager service. Inherits from ScanManager to
    provide common scan operations.

    Class Attributes:
        SCAN_CONFIGS: Available OpenVAS scan configuration IDs.
        PORT_LISTS: Available port list IDs for scanning.

    Attributes:
        hostname: OpenVAS manager hostname.
        port: OpenVAS manager port.
        username: OpenVAS manager username.
        password: OpenVAS manager password.
        scan_type: Type identifier for this manager ('openvas').

    Example:
        >>> manager = OpenVASScanManager(user)
        >>> scan_id = manager.run_scan(target="192.168.1.1")
    """

    SCAN_CONFIGS = {
        'full_fast': 'daba56c8-73ec-11df-a475-002264764cea',
        'full_deep': '8715c877-47a0-438d-98a3-27c7a6ab2196',
        'full_ultimate': '085569ce-73ed-11df-83c3-002264764cea'
    }

    PORT_LISTS = {
        'tcp_all': '33d0cd82-57c6-11e1-8ed1-406186ea4fc5',
        'tcp_udp_all': '4a4717fe-57d2-11e1-9a26-406186ea4fc5',
        'tcp_all_udp_top100': '730ef368-57e2-11e1-a90f-406186ea4fc5'
    }

    def __init__(self, user: User, session: Optional[Session] = None):
        """Initialize OpenVAS manager.

        Args:
            user: User performing the scan.
            session: Optional database session.
        """
        super().__init__(user, session)

        config = ConfigReader.get_openvas_config()
        self.hostname = config["hostname"]  # type: ignore
        self.port = config["port"]          # type: ignore
        self.username = config["username"]  # type: ignore
        self.password = config["password"]  # type: ignore

    def run_scan(self, target: str, scan_config: str = 'full_fast', skip_normalize: bool = False) -> int:
        """Start an OpenVAS scan.

        Args:
            target: Target IP address or hostname.
            scan_config: Scan configuration name (default: 'full_fast').
            skip_normalize: Skip target normalization if True.

        Returns:
            Scan ID of the created scan record.
        """
        try:
            target_ip = target if skip_normalize else normalize_target(target)[0]
            config_id = self.SCAN_CONFIGS.get(scan_config, self.SCAN_CONFIGS['full_fast'])
            scan = self._create_scan_record(target=target)
            scan_id = scan.id

            task = OpenVASTask(
                target=target,
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                scan_config=config_id
            )

            thread = threading.Thread(
                target=self._execute_scan_in_thread,
                args=(scan_id, task, skip_normalize),
                daemon=True,
                name=f"OpenVASScan-{scan_id}"
            )

            self._register_task(scan_id, task, thread)
            thread.start()

            self.logger.info(f"Escaneo OpenVAS {scan_id} iniciado")
            return scan_id

        except Exception as e:
            self.logger.error(f"Error iniciando escaneo OpenVAS: {e}", exc_info=True)
            raise

    def _create_scan_record(self, target: str) -> OpenVASScan:
        """Create an OpenVASScan record in the database.

        Args:
            target: Target IP address or hostname.

        Returns:
            Created OpenVASScan instance.
        """
        temp_task_id = f"PENDING_{uuid.uuid4()}"

        scan = OpenVASScan(
            target=target,
            user_id=self.active_user.id,
            task_id=temp_task_id,
            report_id=temp_task_id
        )
        self.session.add(scan)
        self._safe_commit()
        return scan

    def _create_task(self, target: str, scan_config: str, timeout: int) -> OpenVASTask:
        """Create an OpenVAS task.

        Args:
            target: Target IP address or hostname.
            scan_config: Scan configuration ID.
            timeout: Task timeout in seconds.

        Returns:
            OpenVASTask instance.
        """
        return OpenVASTask(
            target=target,
            hostname=self.hostname,
            port=self.port,
            username=self.username,
            password=self.password,
            scan_config=scan_config,
            timeout=timeout
        )

    def _get_result_processor(self):
        return OpenVASResultProcessor(self.logger)

    def get_scans_for_user(self) -> List[OpenVASScan]:
        """Get all OpenVAS scans for the active user.

        Returns:
            List of OpenVASScan instances with loaded relationships.
        """
        try:
            self._check_session()
            scans = (
                self.session.query(OpenVASScan)
                .filter(OpenVASScan.user_id == self.active_user.id)
                .options(
                    joinedload(OpenVASScan.results).joinedload(OpenVASScanResult.vulnerability),
                    joinedload(OpenVASScan.results).joinedload(OpenVASScanResult.host),
                )
                .all()
            )
            self.logger.info(f"Se obtuvieron {len(scans)} escaneos OpenVAS")
            return scans
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error obteniendo escaneos OpenVAS: {e}", exc_info=True)
            raise

    def _execute_scan_in_thread(
        self, 
        scan_id: int, 
        task: OpenVASTask, 
        skip_normalize: bool = False
    ) -> None:
        """Execute OpenVAS scan in a background thread.

        Override for OpenVAS: needs to update task_id and report_id
        after the task executes.

        Args:
            scan_id: ID of the scan to execute.
            task: OpenVASTask instance to run.
            skip_normalize: Skip target normalization if True.
        """
        thread_manager = self.__class__(self.active_user)

        try:
            if not skip_normalize:
                target_ip, _ = normalize_target(task.target)
                task.target = target_ip
            scan = thread_manager.get_scan_by_id(scan_id)
            if not scan:
                thread_manager.logger.error(f"Escaneo {scan_id} no encontrado")
                return

            thread_manager.logger.info(f"Iniciando escaneo OpenVAS {scan_id}")

            task.scan()
            success = task.wait(timeout=task.timeout + 30)

            if not success or task.results is None:
                thread_manager.logger.error(
                    f"Escaneo {scan_id} falló. Estado: {task.status}"
                )
                thread_manager._mark_scan_as(scan, ScanStatus.FAILED)
                thread_manager._safe_commit()
                return

            scan.task_id = task.task_id
            scan.report_id = task.report_id
            scan.status = ScanStatus.FINISHED.value
            thread_manager.session.add(scan)

            thread_manager.logger.info(f"Guardando resultados de escaneo {scan_id}")
            processor = thread_manager._get_result_processor()
            processor.process_and_save(scan, task.results)
            thread_manager._safe_commit()

            thread_manager.logger.info(f"Escaneo OpenVAS {scan_id} completado")

        except Exception as e:
            thread_manager.logger.error(f"Error en escaneo {scan_id}: {e}", exc_info=True)

            try:
                error_scan = thread_manager.get_scan_by_id(scan_id)
                if error_scan:
                    thread_manager._mark_scan_as(error_scan, ScanStatus.FAILED)
            except Exception as update_err:
                thread_manager.logger.error(f"Error actualizando estado: {update_err}")

        finally:
            thread_manager.close_session()
            self._unregister_task(scan_id)

    def generate_report(self, scan_id: int) -> bytes:
        """Generate a PDF report for an OpenVAS scan.

        Args:
            scan_id: ID of the scan.

        Returns:
            Report bytes.

        Raises:
            NotImplementedError: OpenVAS report generation is handled by endpoint.
        """
        raise NotImplementedError("La generación de reportes para OpenVAS se maneja en el endpoint")

    def _extract_domain_data(self, processor, task, scan):
        return processor.process(task.results)

    def _persist_scan_results(self, scan, domain_data):
        """Persiste vulnerabilidades y resultados OpenVAS."""
        vulnerabilities_data, scan_results_data, hosts_ips = domain_data
        
        # 1. Procesar y guardar vulnerabilidades únicas
        vulnerability_map = {}
        for vuln_data in vulnerabilities_data:
            vuln = self._obtain_or_create_vulnerability(vuln_data)
            vulnerability_map[vuln.nvt_oid] = vuln
        
        # 2. Procesar hosts y crear resultados
        for result_data in scan_results_data:
            host = self._get_or_create_host(
                hostname=result_data['host_ip'],
                ip_address=result_data['host_ip']
            )
            
            scan_result = OpenVASScanResult(
                openvas_scan_id=scan.id,
                vulnerability_id=vulnerability_map[result_data['nvt_oid']].id,
                host_id=host.id
            )
            self.session.add(scan_result)
        
        self.session.flush()

    def _obtain_or_create_vulnerability(self, vuln_data: dict):
        """Obtiene o crea una vulnerabilidad OpenVAS."""
        from src.core.model import OpenVASVulnerability
        
        nvt_oid = vuln_data['nvt_oid']
        vuln = self.session.query(OpenVASVulnerability).filter(
            OpenVASVulnerability.nvt_oid == nvt_oid
        ).one_or_none()
        
        if vuln:
            return vuln
        
        vuln = OpenVASVulnerability(**vuln_data)
        self.session.add(vuln)
        self.session.flush()
        return vuln
