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
    """
    Clase base para gestores de escaneos.
    Responsabilidad: Coordinar la ejecución de tareas y la persistencia de resultados.
    """

    _running_tasks: Dict[int, _Task] = {}
    _running_threads: Dict[int, threading.Thread] = {}
    _running_tasks_lock = threading.RLock()

    def __init__(self, user: User, session: Optional[Session] = None):
        super().__init__(session)
        self.active_user = user

    @classmethod
    def _register_task(cls, scan_id: int, task: _Task, thread: Optional[threading.Thread] = None) -> None:
        with cls._running_tasks_lock:
            cls._running_tasks[scan_id] = task
            if thread is not None:
                cls._running_threads[scan_id] = thread

    @classmethod
    def _get_task(cls, scan_id: int) -> Optional[_Task]:
        with cls._running_tasks_lock:
            return cls._running_tasks.get(scan_id)

    @classmethod
    def _unregister_task(cls, scan_id: int) -> None:
        with cls._running_tasks_lock:
            cls._running_tasks.pop(scan_id, None)
            cls._running_threads.pop(scan_id, None)

    @classmethod
    def cancel_all_running(cls, timeout: float = 10.0) -> None:
        """
        Cancela todas las tareas activas y espera a que sus threads terminen.
        Pensado para ser llamado desde el signal handler de shutdown.
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
        try:
            self._check_session()
            scan = self.get_scan_by_id(scan_id)

            if not scan:
                return False

            # Eliminar documentos asociados antes de borrar el scan
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
        task = self._get_task(scan_id)
        if task:
            progress = task.progress
            self.logger.debug(f"Progreso de escaneo {scan_id}: {progress}%")
            return progress
        return None

    def get_scan_status(self, scan_id: int) -> Optional[str]:
        task = self._get_task(scan_id)
        if task:
            return str(task.status)
        if self.is_scan_finished(scan_id):
            return str(TaskStatus.COMPLETED)
        return None

    def get_document_by_id(self, document_id: int):
        
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

        scan = self.get_scan_by_id(scan_id)
        if not scan:
            self.logger.warning(f"Escaneo {scan_id} no encontrado para verificar finalización")
            return False

        is_finished = scan.status == ScanStatus.FINISHED.value
        return is_finished

    def cancel_scan(self, scan_id: int) -> bool:
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
        pass

    @abstractmethod
    def _create_scan_record(self, **kwargs) -> Scan:
        pass

    @abstractmethod
    def _get_result_processor(self) -> ScanResultProcessor:
        pass

    @abstractmethod
    def generate_report(self, scan_id: int) -> bytes:
        pass

    def _execute_scan_in_thread(self, scan_id: int, task: _Task) -> None:
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
                thread_manager.logger.error(
                    f"Escaneo {scan_id} falló. Estado: {task.status}"
                )
                thread_manager._mark_scan_as(scan, ScanStatus.FAILED)
                return

            thread_manager.logger.info(f"Guardando resultados de escaneo {scan_id}")
        
            processor = thread_manager._get_result_processor()
            processor.process_and_save(scan, task.results)

            thread_manager._mark_scan_as(scan, ScanStatus.FINISHED)
            thread_manager._safe_commit()

            thread_manager.logger.info(f"Escaneo {scan_id} completado exitosamente")

        except Exception as e:
            thread_manager.logger.error(f"Error en escaneo {scan_id}: {e}", exc_info=True)

            try:
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
        old_status = scan.status
        scan.status = status.value
        scan.finished_at = datetime.now()
        self.logger.info(f"Estado del escaneo {scan.id} actualizado: {old_status} -> {status.value}")


class NmapScanManager(ScanManager):
    """Gestor de escaneos Nmap"""

    def run_scan(self, target_host: str, target_ports: str, timeout: int = 300) -> int:
        """Inicia un escaneo Nmap"""
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
        scan = NmapScan(
            target=target,
            user=self.active_user,
            started_at=datetime.now()
        )
        self.session.add(scan)
        self._safe_commit()
        return scan

    def _get_result_processor(self) -> NmapResultProcessor:
        return NmapResultProcessor(self.session, self.logger)

    def get_scans_for_user(self) -> List[NmapScan]:
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

    def generate_report(self, scan_id:  int, ai_report: bool = False) -> int:
        
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
                thread_manager.logger.error(f"Tipo de escaneo {scan_type} no soportado para generación de PDF")
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


class NiktoScanManager(ScanManager):
    """Gestor de escaneos Nikto"""

    def run_scan(self, target_domain: str, timeout: int = 60) -> int:
        """Inicia un escaneo Nikto"""
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
        scan = NiktoScan(
            target=target,
            user=self.active_user,
            started_at=datetime.now()
        )
        self.session.add(scan)
        self._safe_commit()
        return scan

    def _get_result_processor(self) -> NiktoResultProcessor:
        return NiktoResultProcessor(self.session, self.logger)

    def get_scans_for_user(self) -> List[NiktoScan]:
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
            self.logger.info(f"Se obtuvieron {len(scans)} escaneos Nikto")
            return scans
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error obteniendo escaneos Nikto: {e}", exc_info=True)
            raise

    def generate_report(self, scan_id: int) -> bytes:
        raise NotImplementedError("La generación de reportes para Nikto se maneja en el endpoint")

class OpenVASScanManager(ScanManager):
    """Gestor de escaneos OpenVAS"""

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
        super().__init__(user, session)

        config = ConfigReader().get_openvas_config()
        self.hostname = config["hostname"]  # type: ignore
        self.port = config["port"]          # type: ignore
        self.username = config["username"]  # type: ignore
        self.password = config["password"]  # type: ignore

    def run_scan(self, target: str, scan_config: str = 'full_fast', skip_normalize: bool = False) -> int:
        """Inicia un escaneo OpenVAS"""
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
        return OpenVASTask(
            target=target,
            hostname=self.hostname,
            port=self.port,
            username=self.username,
            password=self.password,
            scan_config=scan_config,
            timeout=timeout
        )

    def _get_result_processor(self) -> OpenVASResultProcessor:
        return OpenVASResultProcessor(
            self.session, 
            self.logger
        )

    def get_scans_for_user(self) -> List[OpenVASScan]:
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
        """
        Override para OpenVAS: necesita actualizar task_id y report_id
        después de que la tarea se ejecute.
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
        raise NotImplementedError("La generación de reportes para OpenVAS se maneja en el endpoint")
