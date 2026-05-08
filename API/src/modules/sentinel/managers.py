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

import ipaddress
import itertools
import os
import threading
import time
import uuid



from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional

import src.modules.system.config_reading as CR

from src.modules.users import User, UserManager
from src.modules.shared import normalize_target
from src.modules.system.logging import SecOpsLogger
from src.modules.aegis.exceptions import DocumentError
from src.modules.shared import Document
from src.modules.infrastructure import UnitOfWork

from .repositories import ScanRepository, SentinelReportRepository
from .model import (
    NiktoScan,
    NmapScan,
    OpenVASScan,
    Scan,
    ScanStatus,
    SentinelDocument,
)
from .services import (
    NiktoResultProcessor,
    NmapResultProcessor,
    OpenVASResultProcessor,
    ScanResultProcessor,
    NiktoPrintingStrategy,
    NmapPrintingStrategy,
    OpenVASPrintingStrategy,
    PDFCreator,
    NiktoScanTask,
    NmapScanTask,
    OpenVASTask,
    TaskStatus,
    _Task
)
from .exceptions import (
    ScanNotFoundError,
    IPValidationError,
    MaxHostsExceededError,
    PortValidationError,
)


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
        _scan_timeout_margin: Seconds added to task timeout for wait().

    Attributes:
        user: User executing the scan operations.
        logger:      Logger instance for this manager.
    """

    _running_tasks: Dict[int, _Task] = {}
    _running_threads: Dict[int, threading.Thread] = {}
    _running_tasks_lock = threading.RLock()
    _scan_timeout_margin: int = 30

    def __init__(self, user: User) -> None:
        """
        Initialize the scan manager.

        Args:
            user: User performing the scan operations.
        """
        self.user = user
        self.logger = SecOpsLogger(self.__class__.__name__).get_logger()

    # =========================================================================
    # TASK REGISTRY (class-level, thread-safe)
    # =========================================================================

    @classmethod
    def _register_task(
        cls,
        scan_id: int,
        task: _Task,
        thread: Optional[threading.Thread] = None
    ) -> None:
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

    # =========================================================================
    # SCAN QUERIES
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
            scans = ScanRepository(uow).get_by_user(self.user.id) # pyright: ignore[reportArgumentType]

        self.logger.info(
            f"Se obtuvieron {len(scans)} escaneos para el usuario {self.user.id}"
        )
        return scans

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

        return scan.status == ScanStatus.FINISHED.value # pyright: ignore[reportReturnType]

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
                doc_repo = SentinelReportRepository(uow)

                scan = scan_repo.get_by_id(scan_id)
                if not scan:
                    return False

                docs = doc_repo.get_documents_by_scan(scan_id)

                for doc in docs:
                    if doc.filename and os.path.exists(doc.filename): # type: ignore
                        try:
                            os.remove(doc.filename) # type: ignore
                            self.logger.info(f"Archivo eliminado: {doc.filename}")
                        except (OSError, IOError) as e:
                            self.logger.warning(f"No se pudo eliminar archivo {doc.filename}: {e}")
                    doc_repo.delete(doc)

                scan_repo.delete(scan)
                # UnitOfWork commits on __exit__

            self.logger.info(f"Escaneo {scan_id} eliminado")
            return True

        except (OSError, RuntimeError) as e:
            self.logger.error(f"Error eliminando escaneo {scan_id}: {e}")
            raise


    # =========================================================================
    # OWNERSHIP ASSERTIONS
    # =========================================================================

    def assert_scan_ownership(self, scan_id: int) -> Scan:
        """
        Verifica que el escaneo pertenece al usuario. Lanza ScanNotFoundError
        si no pertenece para evitar enumerar IDs ajenos.

        Args:
            scan_id: ID del escaneo a verificar.
            user_id: ID del usuario que debería ser propietario.

        Raises:
            ScanNotFoundError: Si el escaneo no pertenece al usuario.
        """
        with UnitOfWork() as uow:
            scan = ScanRepository(uow).get_by_id(scan_id)
            if not scan:
                raise ScanNotFoundError(scan_id)

            if scan.user_id != self.user.id: # type: ignore
                raise ScanNotFoundError(scan_id)

        return scan

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

            if scan.user_id != self.user.id: # type: ignore
                self.logger.warning(
                    f"El usuario {self.user.username} no tiene permisos "
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
                except (OSError, RuntimeError) as e:
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

        except (OSError, RuntimeError) as e:
            self.logger.error(f"Error cancelando escaneo {scan_id}: {e}", exc_info=True)
            return False

    @classmethod
    def cancel_all_running(cls, timeout: int = 30) -> None:
        """
        Cancel all running scans and wait for tasks to finish.

        Called during graceful shutdown to ensure no orphaned scans.
        Signals all registered tasks to stop and waits for their threads
        to complete within the specified timeout.

        Args:
            timeout: Maximum seconds to wait for tasks to finish.
        """
        with cls._running_tasks_lock:
            task_ids = list(cls._running_tasks.keys())

        if not task_ids:
            cls.logger.info("No hay tareas activas que cancelar") # type: ignore
            return

        cls.logger.info(f"Cancelando {len(task_ids)} tarea(s) activa(s)...") # type: ignore

        for scan_id in task_ids:
            task = cls._get_task(scan_id)
            if task:
                try:
                    task.cancel()
                except (OSError, RuntimeError) as e:
                    cls.logger.warning(f"Error cancelando tarea {scan_id}: {e}") # type: ignore

        cls.logger.info("Esperando a que las tareas finalicen...") # type: ignore
        start_time = time.monotonic()
        remaining = timeout

        while cls._running_tasks and remaining > 0:
            time.sleep(0.5)
            elapsed = time.monotonic() - start_time
            remaining = timeout - elapsed

        if cls._running_tasks:
            cls.logger.warning( # type: ignore
                f"{len(cls._running_tasks)} tarea(s) no respondieron al cancel "
                "— forzada la terminación"
            )

        cls.logger.info("Todas las tareas finalizadas") # type: ignore


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
        thread_manager = self.__class__(self.user)

        try:
            scan = thread_manager.get_scan_by_id(scan_id)
            if not scan:
                thread_manager.logger.error(f"Escaneo {scan_id} no encontrado en el hilo")
                return

            thread_manager.logger.info(f"Iniciando escaneo {scan_id}")

            task.scan()
            success = task.wait(timeout=task.timeout + self._scan_timeout_margin)

            if not success or task.results is None:
                thread_manager.logger.error(f"Escaneo {scan_id} falló. Estado: {task.status}")
                thread_manager.update_scan_status(scan_id, ScanStatus.FAILED)
                return

            thread_manager.logger.info(f"Procesando resultados de escaneo {scan_id}")

            processor  = thread_manager.get_result_processor()
            scan_type = scan.scan_type
            domain_data = processor.process(task.results, scan.target) if scan_type == "nmap" else processor.process(task.results) # type: ignore

            with UnitOfWork() as uow:
                fresh_scan              = ScanRepository(uow).get_by_id(scan_id)
                thread_manager.persist_scan_results(uow, fresh_scan, domain_data)
                fresh_scan.status       = ScanStatus.FINISHED.value # type: ignore
                fresh_scan.finished_at  = datetime.now() # type: ignore

            thread_manager.logger.info(f"Escaneo {scan_id} completado exitosamente")

        except (OSError, RuntimeError) as e:
            thread_manager.logger.error(f"Error en escaneo {scan_id}: {e}", exc_info=True)
            thread_manager.update_scan_status(scan_id, ScanStatus.FAILED)
        finally:
            self._unregister_task(scan_id)

    def update_scan_status(self, scan_id: int, status: ScanStatus) -> None:
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
        except (OSError, RuntimeError) as update_err:
            self.logger.error(f"Error actualizando estado de escaneo {scan_id}: {update_err}")


    # =========================================================================
    # STATIC UTILITIES
    # =========================================================================

    @staticmethod
    def _require_non_empty(
        value: object,
        ErrorClass: type,
        default_msg: str = "El parámetro debe ser una cadena no vacía"
    ) -> str:
        """Validate and strip a string, raising ErrorClass if empty/invalid."""
        if not value or not isinstance(value, str):
            raise ErrorClass(message=default_msg, ip_spec=str(value) if ErrorClass.__name__ == "IPValidationError" else str(value))
        stripped = value.strip()
        if not stripped:
            msg_map = {
                "IPValidationError": "La cadena de IPs está vacía",
                "PortValidationError": "La cadena de puertos está vacía",
            }
            raise ErrorClass(
                message=msg_map.get(ErrorClass.__name__, default_msg),
                port_spec=stripped if ErrorClass.__name__ == "PortValidationError" else str(value)
            )
        return stripped

    @classmethod
    def get_scan_type(cls, scan_id: int) -> Optional[str]:
        """
        Devuelve el tipo del escaneo en función de su id

        Args:
            scan_id: Id del escaneo a revisar

        Returns:
            Tipo del escaneo ("nmap", "nikto", "openvas")
        """

        with UnitOfWork() as uow:
            scan = ScanRepository(uow).get_by_id(scan_id)
            if scan is None:
                raise ScanNotFoundError(scan_id)

            scan_type = scan.scan_type

            if scan_type is None:
                return None

            return scan_type # pyright: ignore[reportReturnType]

    @classmethod
    def resolve_manager(cls, scan_id: int, user: User) -> "ScanManager":
        """
        Obtiene una instancia del manager adecuado según el tipo del escaneo.

        Args:
            scan_id: ID del escaneo.
            user:   Usuario activo.

        Returns:
            Instancia de NmapScanManager, NiktoScanManager u OpenVASScanManager.

        Raises:
            ScanNotFoundError: Si el escaneo no existe o su tipo no es reconocido.
        """
        scan_type = cls.get_scan_type(scan_id)
        if scan_type == "nmap":
            return NmapScanManager(user)
        if scan_type == "nikto":
            return NiktoScanManager(user)
        if scan_type == "openvas":
            return OpenVASScanManager(user)
        raise ScanNotFoundError(scan_id)

    @staticmethod
    def validate_ip(ips_str: str, max_hosts: int = 10) -> List[str]:
        """
        Valida y expande una especificación de IPs/rangos.

        Formatos soportados:
        - IP individual: "192.168.1.1"
        - CIDR: "192.168.1.0/24"
        - Rangos por octeto: "192.168.1.1-10" o "192.168.1-2.1-10"
        - Lista separada por comas: "192.168.1.1,192.168.1.5"
        - Wildcards: "192.168.1.*" (equivalente a 192.168.1.0-255)

        Raises:
            IPValidationError: Si el formato es inválido.
            MaxHostsExceededError: Si se excede max_hosts.

        Returns:
            Lista de IPs expandidas (sin duplicados).
        """
        def _expand_octal(rango_str: str) -> List[str]:
            rango_str = rango_str.replace("*", "0-255")
            octetos = rango_str.split(".")

            if len(octetos) != 4:
                raise IPValidationError(
                    message="Deben ser exactamente 4 octetos",
                    ip_spec=rango_str
                )

            rangos_octetos: List[range | List[int]] = []

            for octeto in octetos:
                if "-" in octeto:
                    partes = octeto.split("-")
                    if len(partes) != 2:
                        raise IPValidationError(
                            message="Rango de octeto inválido",
                            ip_spec=rango_str
                        )
                    try:
                        inicio = int(partes[0])
                        fin = int(partes[1])
                    except ValueError:
                        raise IPValidationError(
                            message="Los límites del rango deben ser numéricos",
                            ip_spec=rango_str
                        )
                    if inicio > fin:
                        raise IPValidationError(
                            message="El inicio del rango no puede ser mayor que el fin",
                            ip_spec=rango_str
                        )
                    rangos_octetos.append(range(inicio, fin + 1))
                else:
                    try:
                        valor = int(octeto)
                    except ValueError:
                        raise IPValidationError(
                            message="El octeto debe ser numérico",
                            ip_spec=rango_str
                        )
                    rangos_octetos.append([valor])

            lista_ips = []
            for combinacion in itertools.product(*rangos_octetos):
                ip_str = ".".join(map(str, combinacion))
                try:
                    ipaddress.ip_address(ip_str)
                    lista_ips.append(ip_str)
                except ValueError:
                    continue

            if not lista_ips:
                raise IPValidationError(
                    message="No se generaron IPs válidas desde el rango",
                    ip_spec=rango_str
                )
            return lista_ips

        ips_str = ScanManager._require_non_empty(ips_str, IPValidationError)

        segmentos = [s.strip() for s in ips_str.split(",")]
        lista_ips = []
        for segmento in segmentos:
            if not segmento:
                raise IPValidationError(
                    message="Segmento vacío encontrado",
                    ip_spec=ips_str
                )

            if "/" in segmento:
                try:
                    red = ipaddress.ip_network(segmento, strict=False)
                    num_hosts = red.num_addresses - 2 if red.num_addresses > 2 else red.num_addresses

                    if num_hosts > max_hosts:
                        raise MaxHostsExceededError(max_hosts=max_hosts, found=num_hosts)
                    else:
                        lista_ips.extend([str(ip) for ip in red.hosts()])
                        if not lista_ips or red.prefixlen >= 31:
                            lista_ips.extend([str(ip) for ip in red])
                except ValueError as e:
                    raise IPValidationError(
                        message=f"Notación CIDR inválida: {str(e)}",
                        ip_spec=segmento
                    )

            elif "-" in segmento:
                try:
                    ips_expandidas = _expand_octal(segmento)
                    if len(ips_expandidas) > max_hosts:
                        raise MaxHostsExceededError(max_hosts=max_hosts, found=len(ips_expandidas))
                    lista_ips.extend(ips_expandidas)
                except (ValueError, OSError) as e:
                    raise IPValidationError(
                        message=f"Error al procesar rango: {str(e)}",
                        ip_spec=segmento
                    )

            else:
                try:
                    ip = ipaddress.ip_address(segmento)
                    lista_ips.append(str(ip))
                except ValueError:
                    raise IPValidationError(
                        message="Dirección IP inválida",
                        ip_spec=segmento
                    )

        if not lista_ips:
            raise IPValidationError(
                message="No se generaron IPs válidas",
                ip_spec=ips_str
            )

        return list(dict.fromkeys(lista_ips))

    @staticmethod
    def validate_port(ports_str: str) -> List[int]:
        """
        Valida y expande una especificación de puertos.

        Reglas de validación:
        - Puertos en rango 1-65535
        - Puertos y rangos en orden ascendente
        - Rangos válidos (inicio < fin)
        - No solapamiento de rangos
        - Formato: "80", "80,443", "1-1000", "80,443-8080,9000"

        Raises:
            PortValidationError: Si el formato es inválido.

        Returns:
            Lista de puertos expandida (sin duplicados, ordenada).
        """
        ports_str = ScanManager._require_non_empty(ports_str, PortValidationError)

        segmentos = ports_str.split(",")
        ultimo_puerto = 0
        lista_puertos: List[int] = []

        for i, segmento in enumerate(segmentos):
            segmento = segmento.strip()

            if not segmento:
                raise PortValidationError(
                    message=f"Segmento vacío encontrado en la posición {i + 1}",
                    port_spec=ports_str
                )

            if "-" in segmento:
                partes = segmento.split("-")

                if segmento.startswith("-"):
                    if len(partes) != 2 or partes[0] != "":
                        raise PortValidationError(
                            message=f"Formato de rango incorrecto: '{segmento}'",
                            port_spec=ports_str
                        )
                    try:
                        fin = int(partes[1])
                    except ValueError:
                        raise PortValidationError(
                            message=f"Puerto de fin no válido en rango: '{segmento}'",
                            port_spec=ports_str
                        )
                    if fin < 1 or fin > 65535:
                        raise PortValidationError(
                            message=f"Puerto de fin fuera de rango (1-65535): {fin}",
                            port_spec=ports_str
                        )
                    inicio = 1

                elif segmento.endswith("-"):
                    if len(partes) != 2 or partes[1] != "":
                        raise PortValidationError(
                            message=f"Formato de rango incorrecto: '{segmento}'",
                            port_spec=ports_str
                        )
                    try:
                        inicio = int(partes[0])
                    except ValueError:
                        raise PortValidationError(
                            message=f"Puerto de inicio no válido en rango: '{segmento}'",
                            port_spec=ports_str
                        )
                    if inicio < 1 or inicio > 65535:
                        raise PortValidationError(
                            message=f"Puerto de inicio fuera de rango (1-65535): {inicio}",
                            port_spec=ports_str
                        )
                    fin = 65535

                else:
                    if len(partes) != 2:
                        raise PortValidationError(
                            message=f"Formato de rango incorrecto (demasiados guiones): '{segmento}'",
                            port_spec=ports_str
                        )
                    try:
                        inicio = int(partes[0])
                        fin = int(partes[1])
                    except ValueError:
                        raise PortValidationError(
                            message=f"Puertos no numéricos en rango: '{segmento}'",
                            port_spec=ports_str
                        )
                    if inicio < 1 or inicio > 65535:
                        raise PortValidationError(
                            message=f"Puerto de inicio fuera de rango (1-65535): {inicio}",
                            port_spec=ports_str
                        )
                    if fin < 1 or fin > 65535:
                        raise PortValidationError(
                            message=f"Puerto de fin fuera de rango (1-65535): {fin}",
                            port_spec=ports_str
                        )
                    if inicio >= fin:
                        raise PortValidationError(
                            message=f"Rango inválido: el inicio ({inicio}) debe ser menor que el fin ({fin})",
                            port_spec=ports_str
                        )

                if inicio <= ultimo_puerto:
                    raise PortValidationError(
                        message=f"Los puertos no están en orden ascendente: {inicio} aparece después de {ultimo_puerto}",
                        port_spec=ports_str
                    )

                lista_puertos.extend(range(inicio, fin + 1))
                ultimo_puerto = fin

            else:
                try:
                    puerto = int(segmento)
                except ValueError:
                    raise PortValidationError(
                        message=f"Puerto no numérico: '{segmento}'",
                        port_spec=ports_str
                    )
                if puerto < 1 or puerto > 65535:
                    raise PortValidationError(
                        message=f"Puerto fuera de rango (1-65535): {puerto}",
                        port_spec=ports_str
                    )
                if puerto <= ultimo_puerto:
                    raise PortValidationError(
                        message=f"Los puertos no están en orden ascendente: {puerto} aparece después de {ultimo_puerto}",
                        port_spec=ports_str
                    )
                lista_puertos.append(puerto)
                ultimo_puerto = puerto

        return list(dict.fromkeys(lista_puertos))

    # =========================================================================
    # ABSTRACT INTERFACE
    # =========================================================================

    @abstractmethod
    def run_scan(self, **kwargs) -> int:
        """Start a new scan. Returns the scan's primary key."""

    @abstractmethod
    def _create_scan_record(self, **kwargs) -> Scan:
        """Create and persist the initial scan record."""

    @abstractmethod
    def get_result_processor(self) -> ScanResultProcessor:
        """Return the result processor for this scan type."""

    @classmethod
    def _append_document_info(cls, scan, result: dict, user: User) -> None:
        """Append the latest document ID and status to a scan result dict."""
        inst = SentinelReportManager(user)
        doc = inst.get_latest_document_by_scan_id(scan.id)
        if doc:
            result["documentId"] = doc.id
            result["documentStatus"] = doc.status

    @abstractmethod
    def persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist domain data into the database within the given UnitOfWork."""

    @abstractmethod
    def format_scan(self, scan_id: int) -> dict:
        """
        Formatea un escaneo como diccionario JSON.

        Args:
            scan_id: ID del escaneo.

        Returns:
            Diccionario con los datos del escaneo en formato JSON.
        """


# =============================================================================
# NMAP
# =============================================================================

class NmapScanManager(ScanManager):
    _strategy_class = NmapPrintingStrategy

    """
    Manager for Nmap network security scans.

    Handles Nmap scan execution, result processing, and async PDF generation.

    Example:
    >>> manager = NmapScanManager(user)
    >>> scan_id = manager.run_scan(target_host="192.168.1.1", target_ports="1-1000")
    """

    def run_scan(self, target_host: str, target_ports: str, timeout: int = 300) -> int:  # pylint: disable=arguments-differ
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

            self._register_task(scan_id, task, thread) # type: ignore
            thread.start()

            self.logger.info(f"Escaneo Nmap {scan_id} iniciado")
            return scan_id # type: ignore

        except (OSError, RuntimeError) as e:
            self.logger.error(f"Error iniciando escaneo Nmap: {e}", exc_info=True)
            raise

    def _create_scan_record(self, target: str) -> NmapScan: # pylint: disable=arguments-differ
        """Create and persist an NmapScan row."""
        scan = NmapScan(target=target, user_id=self.user.id, started_at=datetime.now())
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
        return scan

    def get_result_processor(self) -> NmapResultProcessor:
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
            scans = ScanRepository(uow).get_nmap_by_user(self.user.id) # type: ignore

        self.logger.info(f"Se obtuvieron {len(scans)} escaneos Nmap")
        return scans

    def persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist Nmap host and port data into the database."""
        host_data, ports_data = domain_data
        scan_repo = ScanRepository(uow)
        host = scan_repo.get_or_create_host(
            hostname    = host_data["hostname"],
            ip_address  = host_data["ip_address"],
            mac_address = host_data["mac_address"],
            vendor      = host_data["vendor"],
        )
        scan_repo.persist_nmap_results(scan, host, ports_data)

    def format_scan(self, scan_id: int) -> dict:
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        result = {
            "id": scan.id,
            "scanType": "nmap",
            "target": scan.target,
            "status": getattr(scan, "status", "unknown"),
            "startedAt": scan.started_at.isoformat(),
            "finishedAt": scan.finished_at.isoformat() if scan.finished_at else None, # type: ignore
            "openPorts": [
                {"port": f"{p.port_id}/{p.port.protocol}", "reason": p.reason}
                for p in scan.open_ports_relation
            ],
            "totalOpenPorts": len(scan.open_ports_relation),
        }
        self._append_document_info(scan, result, self.user)
        return result


# =============================================================================
# NIKTO
# =============================================================================

class NiktoScanManager(ScanManager):
    _strategy_class = NiktoPrintingStrategy

    """
    Manager for Nikto web vulnerability scans.

    Example:
    >>> manager = NiktoScanManager(user)
    >>> scan_id = manager.run_scan(target_domain="example.com")
    """

    def run_scan(self, target_domain: str, timeout: int = 60) -> int:  # pylint: disable=arguments-differ
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

            self._register_task(scan_id, task, thread) # type: ignore
            thread.start()

            self.logger.info(f"Escaneo Nikto {scan_id} iniciado")
            return scan_id # type: ignore

        except (OSError, RuntimeError) as e:
            self.logger.error(f"Error iniciando escaneo Nikto: {e}", exc_info=True)
            raise

    def _create_scan_record(self, target: str) -> NiktoScan: # pylint: disable=arguments-differ
        """Create and persist a NiktoScan row."""
        scan = NiktoScan(target=target, user_id=self.user.id, started_at=datetime.now())
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
        return scan

    def get_result_processor(self) -> NiktoResultProcessor:
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
            scans = ScanRepository(uow).get_nikto_by_user(self.user.id) # type: ignore

        self.logger.info(f"Se obtuvieron {len(scans)} escaneos Nikto")
        return scans

    def persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist Nikto incidents and associate a host."""
        incidents_data = domain_data
        scan_repo = ScanRepository(uow)

        ip, host = normalize_target(scan.target, resolve_hostname=True)
        host = scan_repo.get_or_create_host(
            hostname   = host or ip or scan.target,
            ip_address = ip or scan.target,
        )

        scan_repo.persist_nikto_results(scan, host, incidents_data)

    def format_scan(self, scan_id: int) -> dict:
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        result = {
            "id": scan.id,
            "scanType": "nikto",
            "target": scan.target,
            "status": getattr(scan, "status", "unknown"),
            "startedAt": scan.started_at.isoformat(),
            "finishedAt": scan.finished_at.isoformat() if scan.finished_at else None,
            "incidents": [
                {
                    "osvdbId": i.osvdb_id,
                    "method": i.method,
                    "url": i.url,
                    "description": i.description,
                    "severity": getattr(i, "severity", "UNKNOWN"),
                    "discoveredAt": i.discovered_at.isoformat() if i.discovered_at else None,
                }
                for i in scan.incidents
            ],
            "totalIncidents": len(scan.incidents),
        }
        self._append_document_info(scan, result, self.user)
        return result


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
    ... scan_id = manager.run_scan(target="192.168.1.1")
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

    _strategy_class = OpenVASPrintingStrategy

    def __init__(self, user: User) -> None:
        super().__init__(user)

        config         = CR.get_openvas_config()
        self.hostname  = config["hostname"]
        self.port      = config["port"]
        self.username  = config["username"]
        self.password  = config["password"]

    def run_scan(               # pylint: disable=arguments-differ
        self,
        target: str,
        scan_config: str = "full_fast",
        skip_normalize: bool = False
    ) -> int:
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

            self._register_task(scan_id, task, thread) # type: ignore
            thread.start()

            self.logger.info(f"Escaneo OpenVAS {scan_id} iniciado")
            return scan_id # type: ignore

        except (OSError, RuntimeError) as e:
            self.logger.error(f"Error iniciando escaneo OpenVAS: {e}", exc_info=True)
            raise

    def _create_scan_record(self, target: str) -> OpenVASScan: # pylint: disable=arguments-differ
        """Create and persist an OpenVASScan row with placeholder task/report IDs."""
        placeholder = f"PENDING_{uuid.uuid4()}"
        scan = OpenVASScan(
            target    = target,
            user_id   = self.user.id,
            task_id   = placeholder,
            report_id = placeholder,
        )
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
        return scan

    def get_result_processor(self) -> OpenVASResultProcessor:
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
            scans = ScanRepository(uow).get_openvas_by_user(self.user.id) # type: ignore

        self.logger.info(
            f"Se obtuvieron {len(scans)} escaneos OpenVAS"
        )
        return scans

    def _execute_scan_in_thread(
        self,
        scan_id: int,
        task: OpenVASTask,
        skip_normalize: bool = False
    ) -> None:
        """
        Override: after the base execution, persist the OpenVAS task/report IDs.

        Args:
            scan_id:        Primary key of the scan.
            task:           OpenVASTask instance.
            skip_normalize: Skip IP normalization if True.
        """
        if not skip_normalize:
            target_ip, _ = normalize_target(task.target)
            task.target  = target_ip # type: ignore

        super()._execute_scan_in_thread(scan_id, task)

        if task.task_id:
            try:
                with UnitOfWork() as uow:
                    scan = ScanRepository(uow).get_by_id(scan_id)
                    if scan:
                        scan.task_id   = task.task_id
                        scan.report_id = task.report_id
            except (OSError, RuntimeError) as e:
                self.logger.error(
                    f"Error actualizando task_id/report_id para escaneo {scan_id}: {e}"
                )

    def persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist OpenVAS vulnerabilities, hosts, and scan results."""
        vulnerabilities_data, scan_results_data, _ = domain_data
        scan_repo = ScanRepository(uow)

        vulnerability_map = {}
        for vuln_data in vulnerabilities_data:
            vuln = scan_repo.get_or_create_vulnerability(vuln_data)
            vulnerability_map[vuln.nvt_oid] = vuln

        scan_repo.persist_openvas_results(scan, scan_results_data, vulnerability_map)

    def format_scan(self, scan_id: int) -> dict:
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        result = {
            "id": scan.id,
            "scanType": "openvas",
            "target": scan.target,
            "taskId": scan.task_id,
            "reportId": scan.report_id,
            "status": getattr(scan, "status", "unknown"),
            "startedAt": scan.started_at.isoformat(),
            "finishedAt": scan.finished_at.isoformat() if scan.finished_at else None,
            "vulnerabilities": [
                {
                    "nvtOid": r.vulnerability.nvt_oid,
                    "name": r.vulnerability.name,
                    "severityScore": r.vulnerability.severity_score,
                    "severityClass": r.vulnerability.severity_class,
                    "cvssBaseScore": r.vulnerability.cvss_base_score,
                    "cvssVector": r.vulnerability.cvss_vector,
                    "cveIds": r.vulnerability.cve_ids,
                    "description": r.vulnerability.description,
                    "solution": r.vulnerability.solution,
                    "solutionType": r.vulnerability.solution_type,
                    "affectedSoftware": r.vulnerability.affected_software,
                    "hostIp": r.host.ip_address if r.host else None,
                    "hostName": r.host.hostname if r.host else None,
                }
                for r in scan.results
            ],
            "totalVulnerabilities": len(scan.results),
            "criticalCount": sum(1 for r in scan.results if r.vulnerability.severity_class == "Critical"),
            "highCount": sum(1 for r in scan.results if r.vulnerability.severity_class == "High"),
        }
        self._append_document_info(scan, result, self.user)
        return result


# =============================================================================
# SENTINEL REPORT MANAGER
# =============================================================================

class SentinelReportManager:
    """
    Manager for Sentinel document lifecycle and PDF report generation.

    Handles document CRUD operations, ownership verification, and async
    PDF generation for security scan reports.

    Attributes:
        user: User performing the operations.
        logger:      Logger instance.
    """

    def __init__(self, user: User) -> None:
        self.user = user
        self.logger = SecOpsLogger(self.__class__.__name__).get_logger()

    @staticmethod
    def _create_document(scan, ai_report: bool) -> int:
        """Create a SentinelDocument for a scan and return its ID."""
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
            SentinelReportRepository(uow).save(document)

        return document.id  # type: ignore

    def get_document_by_id(self, document_id: int) -> Optional[SentinelDocument]:
        """Retrieve a SentinelDocument by its primary key."""
        with UnitOfWork() as uow:
            doc = SentinelReportRepository(uow).get_by_id(document_id)

        if not doc:
            self.logger.warning(f"Documento {document_id} no encontrado")

        return doc

    def get_latest_document_by_scan_id(self, scan_id: int) -> Optional[SentinelDocument]:
        """Retrieve the most recently created document for a scan."""
        with UnitOfWork() as uow:
            doc = SentinelReportRepository(uow).get_latest_document(scan_id)

        if doc:
            self.logger.info(f"Último documento para scan {scan_id}: {doc.id}")
        else:
            self.logger.warning(f"No hay documentos para scan {scan_id}")

        return doc

    def get_documents_for_user(self) -> List[SentinelDocument]:
        """Retrieve all documents belonging to the active user."""
        with UnitOfWork() as uow:
            docs = SentinelReportRepository(uow).get_documents_by_user(self.user.id)  # type: ignore

        self.logger.info(f"Se obtuvieron {len(docs)} documentos")
        return docs

    def get_documents_by_scan_id(self, scan_id: int) -> List[SentinelDocument]:
        """Retrieve all documents associated with a specific scan."""
        with UnitOfWork() as uow:
            docs = SentinelReportRepository(uow).get_documents_by_scan(scan_id)

        self.logger.info(f"Se obtuvieron {len(docs)} documentos para scan {scan_id}")
        return docs

    def delete_document(self, document_id: int) -> bool:
        """
        Delete a document and its associated file on disk.

        Returns:
            True if deleted successfully.

        Raises:
            DocumentError: If the document was not found.
        """
        with UnitOfWork() as uow:
            doc_repo = SentinelReportRepository(uow)
            doc = doc_repo.get_by_id(document_id)

            if not doc:
                raise DocumentError(f"Documento {document_id} no encontrado")

            if doc.filename and os.path.exists(doc.filename):  # pyright: ignore[reportArgumentType, reportGeneralTypeIssues]
                try:
                    os.remove(doc.filename)  # type: ignore
                except (OSError, IOError) as e:
                    self.logger.warning(f"No se pudo eliminar el archivo {doc.filename}: {e}")

            doc_repo.delete(doc)

        return True

    def assert_document_ownership(self, document_id: int) -> Document:
        """
        Verify document ownership and return the document.

        Args:
            document_id: ID of the document.

        Returns:
            Document instance.

        Raises:
            DocumentError: If document not found or not owned by user.
        """
        with UnitOfWork() as uow:
            doc_repo = SentinelReportRepository(uow)
            doc = doc_repo.get_by_id(document_id)
            if not doc:
                raise DocumentError(f"Documento {document_id} no encontrado")
            if doc.user_id != self.user.id:  # type: ignore
                raise DocumentError(f"Documento {document_id} no encontrado")

        return doc

    def generate_report(self, scan_id: int, ai_report: bool = False, strategy_class=None) -> int:
        """
        Create a SentinelDocument and start async PDF generation.

        Args:
            scan_id:        Primary key of the scan.
            ai_report:      Include AI-generated analysis.
            strategy_class: Printing strategy class for the scan type.

        Returns:
            Primary key of the created SentinelDocument.
        """
        scan_manager = ScanManager.resolve_manager(scan_id, self.user)
        scan = scan_manager.get_scan_by_id(scan_id)
        if not scan:
            raise ValueError(f"Escaneo {scan_id} no encontrado")

        doc_id = self._create_document(scan, ai_report)

        thread = threading.Thread(
            target=self._generate_pdf_async,
            args=(doc_id, scan.id, ai_report),
            daemon=True,
            name=f"PDFGeneration-Scan-{scan.id}",
        )
        thread.start()
        return doc_id  # type: ignore

    @staticmethod
    def build_pdf_creator(scan) -> "PDFCreator":
        """Build PDFCreator with the correct strategy based on scan type."""

        scan_type = getattr(scan, "scan_type", "").lower()
        if scan_type == "nmap":
            strategy = NmapPrintingStrategy(scan=scan)
        elif scan_type == "nikto":
            strategy = NiktoPrintingStrategy(scan=scan)
        elif scan_type == "openvas":
            strategy = OpenVASPrintingStrategy(scan=scan)
        else:
            from src.modules.shared._exceptions import ValidationError
            raise ValidationError(
                field="scan_type",
                message=f"Tipo de escaneo desconocido: {scan_type}",
                value=scan_type
            )
        return PDFCreator(strategy)

    def _generate_pdf_async(
        self,
        document_id: int,
        scan_id: int,
        ai_report: bool,
    ) -> None:
        """Generate PDF in a background thread and update document status."""

        try:
            scan_manager = ScanManager.resolve_manager(scan_id, self.user)
            scan = scan_manager.get_scan_by_id(scan_id)
            if not scan:
                raise ScanNotFoundError(scan_id)

            document = self.get_document_by_id(document_id)
            if not document:
                raise DocumentError("Documento no encontrado")

            pdf_creator = SentinelReportManager.build_pdf_creator(scan)
            pdf_path = pdf_creator.print_pdf(ai_report=ai_report)

            with UnitOfWork() as uow:
                doc = SentinelReportRepository(uow).get_by_id(document_id)
                if doc:
                    doc.filename     = pdf_path  # type: ignore
                    doc.status       = "done"  # type: ignore
                    doc.generated_at = datetime.utcnow()  # type: ignore

            self.logger.info(f"PDF generado exitosamente para documento {document_id}")

        except (OSError, RuntimeError) as e:
            self.logger.error(
                f"Error generando PDF para documento {document_id}: {e}",
                exc_info=True
            )
            try:
                with UnitOfWork() as uow:
                    doc = SentinelReportRepository(uow).get_by_id(document_id)
                    if doc:
                        doc.status = "error"  # type: ignore
            except (OSError, RuntimeError):
                pass
