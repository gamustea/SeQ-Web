import secrets
import threading
import time
import random
import json
import re
import urllib.request
from dataclasses import dataclass, field, asdict
import os
import urllib.parse
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Literal

from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional, Dict
import time

import jwt
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import ollama

from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.orm import Session, scoped_session, sessionmaker, joinedload

from src.logic.documents import AegisAIWriter, AegisAlertFetcher, AegisContent
from src.core.exceptions import ExistingUserError, UserBindingError, DatabaseError
from src.core.model import (
    AccessToken,
    NiktoScan,
    NmapScan,
    OpenPort,
    Person,
    RefreshToken,
    Scan,
    User,
    OpenVASScan,
    OpenVASScanResult,
    Vault,
    Storable,
    Account,
    CreditCard,
    AegisDocument,
    Topic
)
from src.logic.secrets import Encoder
from src.logic.tasks import NmapScanTask, NiktoScanTask, TaskStatus, _Task, OpenVASTask
from src.misc.configread import ConfigReader
from src.misc.logging import SecOpsLogger
from src.misc.inetutils import normalize_target
from src.logic.processors import (
    NmapResultProcessor, 
    NiktoResultProcessor,
    OpenVASResultProcessor,
    ScanResultProcessor
) 

StorableKind = Literal["account", "creditcard"]

config_reader = ConfigReader()
(   
    ACCESS_TOKEN_EXPIRE_MINUTES, 
    REFRESH_TOKEN_EXPIRE_DAYS, 
    JWT_SECRET_KEY, 
    JWT_ALGORITHM
) = config_reader.get_oauth_config()


_ENGINE = None
_SESSION_FACTORY = None


def initialize_engine(database_url: Optional[str] = None): 
    """
    Inicializa el engine y el session factory una sola vez.
    Debe ser llamado al inicio de la aplicación.
    """
    global _ENGINE, _SESSION_FACTORY
    
    if _ENGINE is None:
        if database_url is None:
            (USERNAME, PASSWORD, HOST, DBNAME) = ConfigReader().get_db_crendetials()
            database_url = (
                f"postgresql+psycopg2://{USERNAME}:{urllib.parse.quote(PASSWORD)}@{HOST}/{DBNAME}"
            )
        
        _ENGINE = create_engine(
            database_url,
            pool_pre_ping=True,
            pool_recycle=3600,
            echo=False,
            isolation_level="READ COMMITTED"
        )
        
        _SESSION_FACTORY = scoped_session(
            sessionmaker(
                bind=_ENGINE,
                expire_on_commit=False,
                autoflush=True,
                autocommit=False
            )
        )


class BaseManager:
    """
    Clase base para todos los managers que necesitan acceso a la BD.
    Proporciona gestión de sesiones thread-safe y métodos de utilidad.
    """
    
    def __init__(self, session: Optional[Session] = None):
        global _SESSION_FACTORY
        
        if _SESSION_FACTORY is None:
            initialize_engine()
        
        if session is not None:
            self.session = session
            self._owns_session = False
        else:
            self.session = _SESSION_FACTORY() # type: ignore
            self._owns_session = True
        
        self.logger = SecOpsLogger(self.__class__.__name__).get_logger()
    
    def _check_session(self):
        if self.session is None:
            raise Exception("La sesión de base de datos no está establecida.")
    
    def close_session(self):
        if self._owns_session and self.session is not None:
            try:
                self.session.close()
                _SESSION_FACTORY.remove() # type: ignore
            except Exception as e:
                self.logger.warning(f"Error al cerrar sesión: {e}")
    
    def _safe_commit(self):
        try:
            self.session.commit()
            return True
        except SQLAlchemyError as err:
            self.logger.error(f"Error durante commit: {err}")
            self._safe_rollback()
            raise
    
    def _safe_rollback(self):
        try:
            if self.session is not None:
                self.session.rollback()
                self.logger.debug("Rollback ejecutado exitosamente")
        except Exception as e:
            self.logger.warning(f"Error durante rollback: {e}")
            try:
                if self._owns_session:
                    self.session.close()
                    global _SESSION_FACTORY
                    if _SESSION_FACTORY is not None:
                        self.session = _SESSION_FACTORY()
                        self.logger.info("Sesión recreada después de error en rollback")
            except Exception as recreate_err:
                self.logger.error(f"No se pudo recrear la sesión: {recreate_err}")
    
    @staticmethod
    def close_all_sessions():
        global _SESSION_FACTORY
        if _SESSION_FACTORY is not None:
            _SESSION_FACTORY.remove()


class ScanManager(BaseManager, ABC):
    """
    Clase base para gestores de escaneos.
    Responsabilidad: Coordinar la ejecución de tareas y la persistencia de resultados.
    """

    _running_tasks: Dict[int, _Task] = {}
    _running_threads: Dict[int, threading.Thread] = {}  # registro de threads activos
    _running_tasks_lock = threading.RLock()

    def __init__(self, user: User, session: Optional[Session] = None):
        super().__init__(session)
        self.active_user = user

    # ------------ Helpers de clase para el registro global ------------

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
        if self._is_scan_finished(scan_id):
            return str(TaskStatus.COMPLETED)
        return None
    
    def is_scan_finished(self, scan_id: int) -> Optional[bool]:
        return self._is_scan_finished(scan_id)
    
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
            
            self._update_scan_status(scan_id, 'cancelled')
            
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
    def _create_task(self, **kwargs) -> _Task:
        pass
    
    @abstractmethod
    def _get_result_processor(self) -> ScanResultProcessor:
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
            
            if not success or task.results is None:
                thread_manager.logger.error(
                    f"Escaneo {scan_id} falló. Estado: {task.status}"
                )
                thread_manager._mark_scan_as_failed(scan)
                return
            
            scan.status = "finished"
            
            thread_manager.logger.info(f"Guardando resultados de escaneo {scan_id}")
            processor = thread_manager._get_result_processor()
            processor.process_and_save(scan, task.results)
            thread_manager._safe_commit()
            
            thread_manager.logger.info(f"Escaneo {scan_id} completado exitosamente")
        
        except Exception as e:
            thread_manager.logger.error(f"Error en escaneo {scan_id}: {e}", exc_info=True)
            
            try:
                error_scan = thread_manager.get_scan_by_id(scan_id)
                if error_scan:
                    thread_manager._mark_scan_as_failed(error_scan)
            except Exception as update_err:
                thread_manager.logger.error(f"Error actualizando estado: {update_err}")
        
        finally:
            thread_manager.close_session()
            self._unregister_task(scan_id)
    
    def _mark_scan_as_failed(self, scan: Scan) -> None:
        scan.status = "failed"
        scan.finished_at = datetime.now()
        self.session.add(scan)
        self._safe_commit()
    
    def _is_scan_finished(self, scan_id: int) -> bool:
        try:
            self._check_session()
            scan = self.session.get(Scan, scan_id)

            if scan is None:
                return

            return scan.finished_at is not None
        
        except Exception as e:
            self.logger.error(f"Error verificando estado: {e}")
            return False

    def _update_scan_status(self, scan_id: int, status: str) -> bool:
        try:
            self._check_session()
            scan = self.get_scan_by_id(scan_id)
            
            if not scan:
                self.logger.warning(f"No se puede actualizar estado: escaneo {scan_id} no encontrado")
                return False
            
            old_status = scan.status
            scan.status = status
            self._safe_commit()
            
            self.logger.info(f"Estado del escaneo {scan_id} actualizado: {old_status} -> {status}")
            return True
        
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error actualizando estado del escaneo {scan_id}: {e}")
            return False
    
    def _setup_task_callbacks(self, task: _Task, scan_id: int):
        original_wait = task.wait
        
        def wait_with_callback(timeout: Optional[float] = None) -> bool:
            result = original_wait(timeout)
            
            try:
                if task.status == TaskStatus.COMPLETED:
                    self._update_scan_status(scan_id, 'completed')
                elif task.status == TaskStatus.FAILED:
                    self._update_scan_status(scan_id, 'failed')
                elif task.status == TaskStatus.CANCELLED:
                    self._update_scan_status(scan_id, 'cancelled')
                elif task.status == TaskStatus.TIMEOUT:
                    self._update_scan_status(scan_id, 'failed')
                
                if scan_id in self._running_tasks:
                    del self._running_tasks[scan_id]
            
            except Exception as e:
                self.logger.error(f"Error en callback de finalización: {e}")
            
            return result
        
        task.wait = wait_with_callback


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
        
        config = ConfigReader().get_openvas_config()["access"]
        self.hostname = config["hostname"] # type: ignore
        self.port = config["port"] # type: ignore
        self.username = config["username"] # type: ignore
        self.password = config["password"] # type: ignore
    
    def run_scan(self, target: str, scan_config: str = 'full_fast') -> int:
        """Inicia un escaneo OpenVAS"""
        try:
            target_ip, _ = normalize_target(target)
            config_id = self.SCAN_CONFIGS.get(scan_config, self.SCAN_CONFIGS['full_fast'])
            
            scan = self._create_scan_record(target=target_ip) # type: ignore
            scan_id = scan.id
            
            task = self._create_task(
                target=target_ip,
                scan_config=config_id,
                timeout=30000000
            )
            
            thread = threading.Thread(
                target=self._execute_scan_in_thread,
                args=(scan_id, task),
                daemon=True,  # fix: daemon=True para no bloquear shutdown
                name=f"OpenVASScan-{scan_id}"
            )

            # fix: registrar ANTES de start() para evitar race condition
            self._register_task(scan_id, task, thread)
            thread.start()
            
            self.logger.info(f"Escaneo OpenVAS {scan_id} iniciado")
            return scan_id
        
        except Exception as e:
            self.logger.error(f"Error iniciando escaneo OpenVAS: {e}", exc_info=True)
            raise
    
    def _create_scan_record(self, target: str) -> OpenVASScan:
        import uuid
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
        return OpenVASResultProcessor(self.session, self.logger)

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
    
    def _execute_scan_in_thread(self, scan_id: int, task: OpenVASTask) -> None:
        """
        Override para OpenVAS: necesita actualizar task_id y report_id
        después de que la tarea se ejecute.
        """
        thread_manager = self.__class__(self.active_user)
        
        try:
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
                thread_manager._mark_scan_as_failed(scan)
                return
            
            scan.task_id = task.task_id
            scan.report_id = task.report_id
            scan.status = "finished"
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
                    thread_manager._mark_scan_as_failed(error_scan)
            except Exception as update_err:
                thread_manager.logger.error(f"Error actualizando estado: {update_err}")
        
        finally:
            thread_manager.close_session()
            self._unregister_task(scan_id)


class NmapScanManager(ScanManager):
    """Gestor de escaneos Nmap"""
    
    def run_scan(self, target_host: str, target_ports: str, timeout: int = 300) -> int:
        """Inicia un escaneo Nmap"""
        try:
            scan = self._create_scan_record(target=target_host)
            scan_id = scan.id
            
            task = self._create_task(
                target_host=target_host,
                target_ports=target_ports,
                timeout=timeout
            )
            
            thread = threading.Thread(
                target=self._execute_scan_in_thread,
                args=(scan_id, task),
                daemon=True,  # fix: daemon=True para no bloquear shutdown
                name=f"NmapScan-{scan_id}"
            )

            # fix: registrar ANTES de start() — ya estaba correcto en Nmap
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
    
    def _create_task(self, target_host: str, target_ports: str, timeout: int) -> NmapScanTask:
        return NmapScanTask(target_host, target_ports, timeout)
    
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


class NiktoScanManager(ScanManager):
    """Gestor de escaneos Nikto"""
    
    def run_scan(self, target_domain: str, timeout: int = 60) -> int:
        """Inicia un escaneo Nikto"""
        try:
            scan = self._create_scan_record(target=target_domain)
            scan_id = scan.id
            
            task = self._create_task(target_domain=target_domain, timeout=timeout)
            
            thread = threading.Thread(
                target=self._execute_scan_in_thread,
                args=(scan_id, task),
                daemon=True,  # fix: daemon=True para no bloquear shutdown
                name=f"NiktoScan-{scan_id}"
            )

            # fix: registrar ANTES de start() para evitar race condition
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
    
    def _create_task(self, target_domain: str, timeout: int) -> NiktoScanTask:
        return NiktoScanTask(target_domain, timeout)
    
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


class UserManager(BaseManager):
    """
    Gestor completo para usuarios y personas con autenticación y gestión de tokens.
    """
    
    def verify_credentials(self, username: str, password: str) -> Tuple[bool, Optional[int]]:
        self._check_session()
        
        try:
            user = self._get_by_field(User, "username", username)
            
            if not user:
                self.logger.info(f"Usuario '{username}' no encontrado")
                return False, None
            
            valid_password = Encoder.verify_password(
                stored_hash=user.password_hash,
                password=password,
                salt=user.password_salt
            )
            
            if not valid_password:
                self.logger.warning(f"Contraseña incorrecta para '{username}'")
                return False, None
            
            user_id = user.id
            self.session.expunge(user)
            
            self.logger.info(f"Credenciales válidas para '{username}' (ID: {user_id})")
            return True, user_id
        
        except Exception as e:
            self.logger.error(f"Error verificando credenciales: {e}")
            raise
    
    def validate_credentials_simple(self, username: str, password: str) -> bool:
        is_valid, _ = self.verify_credentials(username, password)
        return is_valid
    
    def create_user(self, user: User) -> None:
        self._check_session()
        
        try:
            if self._exists(User, "username", user.username):
                raise ExistingUserError(username=user.username)
            
            if user.person_id:
                if not self._exists(Person, "id", user.person_id):
                    if user.person:
                        self._create_person(user.person)
            elif user.person:
                self._create_person(user.person)
            
            self.session.add(user)
            self._safe_commit()
            
            self.logger.info(f"Usuario '{user.username}' creado con ID {user.id}")
        
        except ExistingUserError:
            raise
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error creando usuario: {e}")
            raise
    
    def sign_in_user(self, username: str, password: str, email: str, alias: str) -> User:
        self._check_session()
        
        try:
            if self._exists(User, "username", username):
                raise ExistingUserError(username)
            
            person = self._get_by_field(Person, "alias", alias)
            
            if not person:
                raise UserBindingError(username=username, alias=alias)
            
            salt = Encoder.generate_salt()
            hashed_password = Encoder.hash_password_with_salt(password, salt)
            
            new_user = User(
                username=username,
                password_hash=hashed_password,
                password_salt=salt,
                email=email,
                person_id=person.id
            )
            
            self.session.add(new_user)
            self._safe_commit()
            self.session.expunge(new_user)
            
            self.logger.info(f"Usuario '{username}' registrado exitosamente")
            return new_user
        
        except (ExistingUserError, UserBindingError):
            self._safe_rollback()
            raise
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error registrando usuario: {e}")
            raise DatabaseError("Error con credenciales. Revísalas e inténtalo de nuevo.")
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        return self._get_by_field(User, "username", username)
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        return self._get_by_field(User, "id", user_id)
    
    def get_all_users(self) -> List[User]:
        return self._get_all(User)
    
    def update_user_password(self, user_or_id, new_password: str) -> None:
        self._check_session()

        if isinstance(user_or_id, int):
            user = self.get_user_by_id(user_or_id)
            if not user:
                raise UserBindingError(username=str(user_or_id), alias="unknown")
        else:
            user = user_or_id

        try:
            new_salt = Encoder.generate_salt()
            new_hash = Encoder.hash_password_with_salt(new_password, new_salt)

            user.password_salt = new_salt
            user.password_hash = new_hash

            self.session.add(user)
            self._safe_commit()

            self.logger.info(f"Contraseña actualizada para usuario {user.id}")

        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error actualizando contraseña: {e}")
            raise
    
    def update_user_password_by_id(self, user_id: int, new_password: str) -> None:
        user = self.get_user_by_id(user_id)
        
        if not user:
            raise UserBindingError(username=str(user_id), alias="unknown")
        
        self.update_user_password(user, new_password)
    
    def delete_user(self, user: User) -> None:
        self._delete(user, "Usuario")
    
    def sign_in_person(self, first_name: str, last_name: str, alias: str) -> Person:
        self._check_session()
        
        try:
            if self._exists(Person, "alias", alias):
                raise ExistingUserError(f"El alias {alias} ya está en uso")
            
            person = Person(
                first_name=first_name,
                last_name=last_name,
                alias=alias
            )
            
            self._create_person(person)
            
            self.logger.info(f"Persona registrada: {first_name} {last_name}")
            return person
        
        except ExistingUserError:
            raise
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error registrando persona: {e}")
            raise
    
    def get_person_by_alias(self, alias: str) -> Optional[Person]:
        return self._get_by_field(Person, "alias", alias)
    
    def get_person_by_email(self, email: str) -> Optional[Person]:
        return self._get_by_field(Person, "email", email)
    
    def get_person_by_id(self, person_id: int) -> Optional[Person]:
        return self._get_by_field(Person, "id", person_id)
    
    def get_all_people(self) -> List[Person]:
        return self._get_all(Person)
    
    def update_person(self, person: Person) -> None:
        self._check_session()
        
        try:
            existing = self.get_person_by_id(person.id)
            
            if existing:
                existing.first_name = person.first_name
                existing.last_name = person.last_name
                existing.email = person.email
                
                self._safe_commit()
                self.logger.info(f"Persona {person.id} actualizada")
            else:
                self.logger.warning(f"Persona {person.id} no encontrada")
        
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error actualizando persona: {e}")
            raise
    
    def delete_person(self, person: Person) -> None:
        self._delete(person, "Persona")
    
    def _get_by_field(self, model, field: str, value: Any) -> Optional[Any]:
        self._check_session()
        
        try:
            obj = self.session.query(model).filter(
                getattr(model, field) == value
            ).one_or_none()
            
            if obj:
                self.logger.debug(f"{model.__name__} con {field}='{value}' encontrado")
            else:
                self.logger.debug(f"{model.__name__} con {field}='{value}' no encontrado")
            
            return obj
        
        except Exception as e:
            self.logger.error(f"Error obteniendo {model.__name__}: {e}")
            raise
    
    def _get_all(self, model) -> List[Any]:
        self._check_session()
        
        try:
            objects = self.session.query(model).all()
            self.logger.info(f"Se obtuvieron {len(objects)} {model.__name__}s")
            return objects
        
        except Exception as e:
            self.logger.error(f"Error obteniendo {model.__name__}s: {e}")
            raise
    
    def _exists(self, model, field: str, value: Any) -> bool:
        self._check_session()
        
        exists = self.session.query(model).filter(
            getattr(model, field) == value
        ).count() > 0
        
        return exists
    
    def _delete(self, obj: Any, obj_type: str) -> None:
        self._check_session()
        
        try:
            self.session.delete(obj)
            self._safe_commit()
            
            self.logger.info(f"{obj_type} eliminado")
        
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error eliminando {obj_type}: {e}")
            raise
    
    def _create_person(self, person: Person) -> None:
        self._check_session()
        
        try:
            self.session.add(person)
            self.session.flush()
            self.logger.info(
                f"Persona creada: {person.first_name} {person.last_name} (ID: {person.id})"
            )
        
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error creando persona: {e}")
            raise


class VaultManager(BaseManager):
    """
    Gestor de almacenes (Vaults) y elementos almacenables (Storables).
    """

    def __init__(self, user: User, session: Optional[Session] = None):
        super().__init__(session)
        self.active_user = user

    @staticmethod
    def _parse_dt(value: Optional[str]) -> datetime:
        if not value:
            return datetime.utcnow()
        try:
            return datetime.fromisoformat(value)
        except Exception:
            return datetime.utcnow()

    def _ensure_vault_ownership(self, vault: Vault) -> None:
        if vault.user_id != self.active_user.id:
            raise PermissionError(
                f"El usuario {self.active_user.id} no es dueño del vault {vault.id}"
            )

    def get_vault_by_id(self, vault_id: int) -> Optional[Vault]:
        self._check_session()
        vault = self.session.get(Vault, vault_id)
        if vault is None:
            self.logger.warning(f"Vault {vault_id} no encontrado")
            return None
        self._ensure_vault_ownership(vault)
        return vault

    def get_vault_for_user(self, is_recovery: bool = False) -> Optional[Vault]:
        self._check_session()
        vault = (
            self.session.query(Vault)
            .filter(
                Vault.user_id == self.active_user.id,
                Vault.is_recovery == is_recovery,
            )
            .one_or_none()
        )
        return vault

    def upsert_vault_from_json(
        self,
        data: Dict[str, Any],
        is_recovery: bool = False,
    ) -> Tuple[Vault, bool]:
        self._check_session()

        try:
            algorithm = data.get("algorithm", {}) or {}

            vault = self.get_vault_for_user(is_recovery=is_recovery)
            created = vault is None

            if vault is None:
                vault = Vault(
                    user_id=self.active_user.id,
                    is_recovery=is_recovery,
                    checker=data["checker"],
                    vault_key=data["vaultKey"],
                    transformation=algorithm.get("transformation", ""),
                    kdf=algorithm.get("kdf", ""),
                    kdf_iterations=int(algorithm.get("kdfIterations", 0)),
                    kdf_memory=int(algorithm.get("kdfMemoryKiB", 0)),
                    kdf_parallelism=int(algorithm.get("kdfParallelism", 1)),
                    salt=algorithm.get("salt", ""),
                )
                self.session.add(vault)
                self.session.flush()
            else:
                self._ensure_vault_ownership(vault)
                vault.checker = data["checker"]
                vault.vault_key = data["vaultKey"]
                vault.transformation = algorithm.get("transformation", "")
                vault.kdf = algorithm.get("kdf", "")
                vault.kdf_iterations = int(algorithm.get("kdfIterations", 0))
                vault.kdf_memory = int(algorithm.get("kdfMemoryKiB", 0))
                vault.kdf_parallelism = int(algorithm.get("kdfParallelism", 1))
                vault.salt = algorithm.get("salt", "")

                for st in list(vault.storables):
                    self.session.delete(st)
                self.session.flush()

            for acc in data.get("accounts", []) or []:
                created_at = self._parse_dt(acc.get("createdAt"))
                updated_at = self._parse_dt(acc.get("updatedAt"))

                account = Account(
                    vault=vault,
                    internal_id=acc.get("id"),
                    title=acc.get("title"),
                    created_at=created_at,
                    updated_at=updated_at,
                    username=acc.get("username", ""),
                    domain=acc.get("domain", ""),
                    password=acc.get("password", ""),
                )
                self.session.add(account)

            for card in data.get("creditcards", []) or []:
                created_at = self._parse_dt(card.get("createdAt"))
                updated_at = self._parse_dt(card.get("updatedAt"))

                cc = CreditCard(
                    vault=vault,
                    internal_id=card.get("id"),
                    title=card.get("title"),
                    created_at=created_at,
                    updated_at=updated_at,
                    cardholder_name=card.get("cardHolderName", ""),
                    card_number=card.get("cardNumber", ""),
                    expiration_date=card.get("expirationDate", ""),
                    postal_code=card.get("postalCode", ""),
                    cvv=card.get("cvv", ""),
                )
                self.session.add(cc)

            self._safe_commit()
            self.session.refresh(vault)

            self.logger.info(
                f"Vault {vault.id} {'creado' if created else 'actualizado'} "
                f"para user {self.active_user.id} (is_recovery={is_recovery})"
            )
            return vault, created

        except IntegrityError as ie:
            self._safe_rollback()
            self.logger.error(f"Error de integridad en upsert de vault: {ie}")
            raise
        except Exception as e:
            self._safe_rollback()
            self.logger.error(
                f"Error en upsert de vault desde JSON: {e}", exc_info=True
            )
            raise
    
    def upsert_vault_from_json_string(
            self,
            data: str,
            is_recovery: bool = False
    ):
        self.upsert_vault_from_json(
            json.loads(data), 
            is_recovery
        )

    def export_vault_to_json(self, vault_id: int) -> Dict[str, Any]:
        vault = self.get_vault_by_id(vault_id)
        if vault is None:
            raise ValueError(f"Vault {vault_id} no encontrado")

        self._check_session()

        algorithm = {
            "transformation": vault.transformation,
            "kdf": vault.kdf,
            "kdfIterations": str(vault.kdf_iterations),
            "kdfMemoryKiB": str(vault.kdf_memory),
            "kdfParallelism": str(vault.kdf_parallelism),
            "salt": vault.salt,
        }

        accounts_json: List[Dict[str, Any]] = []
        cards_json: List[Dict[str, Any]] = []

        for st in vault.storables:
            base = {
                "id": st.internal_id,
                "title": st.title,
                "createdAt": st.created_at.isoformat() if st.created_at else None,
                "updatedAt": st.updated_at.isoformat() if st.updated_at else None,
                "allowedUsers": [],
            }

            if isinstance(st, Account):
                accounts_json.append(
                    {
                        **base,
                        "username": st.username,
                        "domain": st.domain,
                        "password": st.password,
                    }
                )
            elif isinstance(st, CreditCard):
                cards_json.append(
                    {
                        **base,
                        "cardHolderName": st.cardholder_name,
                        "cardNumber": st.card_number,
                        "expirationDate": st.expiration_date,
                        "postalCode": st.postal_code,
                        "cvv": st.cvv,
                    }
                )

        return {
            "checker": vault.checker,
            "vaultKey": vault.vault_key,
            "algorithm": algorithm,
            "accounts": accounts_json,
            "creditcards": cards_json,
        }

    def export_vault_to_json_string(self, vault_id: int) -> str:
        return str(self.export_vault_to_json(vault_id))

    def find_storables(
        self,
        *,
        vault_id: Optional[int] = None,
        limit: Optional[int] = None,
        **filters: Any,
    ) -> List[Storable]:
        self._check_session()

        query = self.session.query(Storable)

        if vault_id is not None:
            vault = self.get_vault_by_id(vault_id)
            if vault is None:
                return []
            query = query.filter(Storable.vault_id == vault_id)
        else:
            query = query.join(Vault).filter(Vault.user_id == self.active_user.id)

        for field, value in filters.items():
            if not hasattr(Storable, field):
                raise ValueError(f"Campo inválido para Storable: {field}")
            query = query.filter(getattr(Storable, field) == value)

        if limit is not None:
            query = query.limit(limit)

        return query.all()

    def get_storable_by(self, **filters: Any) -> Optional[Storable]:
        results = self.find_storables(limit=2, **filters)
        if not results:
            return None
        if len(results) > 1:
            raise ValueError(
                f"Más de un Storable coincide con los filtros: {filters!r}"
            )
        return results[0]

    def get_storable(self, storable_id: int) -> Optional[Storable]:
        st = self.get_storable_by(id=storable_id)
        return st

    def list_storables(self, vault_id: int) -> List[Storable]:
        vault = self.get_vault_by_id(vault_id)
        if vault is None:
            return []
        return list(vault.storables)

    def add_storable_to_vault(
        self,
        vault_id: int,
        kind: StorableKind,
        *,
        internal_id: Optional[str] = None,
        title: Optional[str] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
        **payload: Any,
    ) -> Storable:
        self._check_session()
        vault = self.get_vault_by_id(vault_id)
        if vault is None:
            raise ValueError(f"Vault {vault_id} no encontrado")

        created_at = created_at or datetime.utcnow()
        updated_at = updated_at or created_at

        if kind == "account":
            st = Account(
                vault=vault,
                internal_id=internal_id,
                title=title,
                created_at=created_at,
                updated_at=updated_at,
                username=payload.get("username", ""),
                domain=payload.get("domain", ""),
                password=payload.get("password", ""),
            )
        elif kind == "creditcard":
            st = CreditCard(
                vault=vault,
                internal_id=internal_id,
                title=title,
                created_at=created_at,
                updated_at=updated_at,
                cardholder_name=payload.get("cardholder_name", ""),
                card_number=payload.get("card_number", ""),
                expiration_date=payload.get("expiration_date", ""),
                postal_code=payload.get("postal_code", ""),
                cvv=payload.get("cvv", ""),
            )
        else:
            raise ValueError(f"Tipo de storable no soportado: {kind}")

        try:
            self.session.add(st)
            self._safe_commit()
            self.session.refresh(st)
            self.logger.info(f"Storable {st.id} creado en vault {vault_id}")
            return st
        except IntegrityError as ie:
            self._safe_rollback()
            self.logger.error(f"Error de integridad añadiendo storable: {ie}")
            raise
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error añadiendo storable: {e}", exc_info=True)
            raise
    
    def update_storable(
        self,
        storable_id: int,
        *,
        title: Optional[str] = None,
        internal_id: Optional[str] = None,
        username: Optional[str] = None,
        domain: Optional[str] = None,
        password: Optional[str] = None,
        cardholder_name: Optional[str] = None,
        card_number: Optional[str] = None,
        expiration_date: Optional[str] = None,
        postal_code: Optional[str] = None,
        cvv: Optional[str] = None,
    ) -> Storable:
        self._check_session()
        st = self.get_storable(storable_id)
        if st is None:
            raise ValueError(f"Storable {storable_id} no encontrado")

        try:
            changed = False
            if title is not None:
                st.title = title
                changed = True
            if internal_id is not None:
                st.internal_id = internal_id
                changed = True

            if isinstance(st, Account):
                if username is not None:
                    st.username = username
                    changed = True
                if domain is not None:
                    st.domain = domain
                    changed = True
                if password is not None:
                    st.password = password
                    changed = True

            if isinstance(st, CreditCard):
                if cardholder_name is not None:
                    st.cardholder_name = cardholder_name
                    changed = True
                if card_number is not None:
                    st.card_number = card_number
                    changed = True
                if expiration_date is not None:
                    st.expiration_date = expiration_date
                    changed = True
                if postal_code is not None:
                    st.postal_code = postal_code
                    changed = True
                if cvv is not None:
                    st.cvv = cvv
                    changed = True

            if changed:
                st.updated_at = datetime.utcnow()
                self.session.add(st)
                self._safe_commit()
                self.session.refresh(st)
                self.logger.info(f"Storable {st.id} actualizado correctamente")
            else:
                self.logger.info(f"Storable {st.id}: sin cambios")

            return st

        except IntegrityError as ie:
            self._safe_rollback()
            self.logger.error(f"Error de integridad actualizando storable {storable_id}: {ie}")
            raise
        except Exception as e:
            self._safe_rollback()
            self.logger.error(
                f"Error actualizando storable {storable_id}: {e}", exc_info=True
            )
            raise

    def bulk_update_storables(
        self,
        operations: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        self._check_session()

        results: List[Dict[str, Any]] = []
        vault_cache: Dict[bool, Optional[Vault]] = {}

        field_map = {
            "title": "title",
            "internalId": "internal_id",
            "username": "username",
            "domain": "domain",
            "password": "password",
            "cardHolderName": "cardholder_name",
            "cardNumber": "card_number",
            "expirationDate": "expiration_date",
            "postalCode": "postal_code",
            "cvv": "cvv",
        }

        for op in operations:
            internal_id = op.get("internalId")
            is_recovery = bool(op.get("isRecovery", False))

            if not internal_id:
                results.append({
                    "internalId": None,
                    "isRecovery": is_recovery,
                    "status": "error",
                    "error": "Missing internalId",
                })
                continue

            changes = op.get("changes") or {}
            if not isinstance(changes, dict) or not changes:
                results.append({
                    "internalId": internal_id,
                    "isRecovery": is_recovery,
                    "status": "skipped",
                    "error": "No changes provided",
                })
                continue

            try:
                if is_recovery not in vault_cache:
                    vault_cache[is_recovery] = self.get_vault_for_user(
                        is_recovery=is_recovery
                    )

                vault = vault_cache[is_recovery]
                if not vault:
                    results.append({
                        "internalId": internal_id,
                        "isRecovery": is_recovery,
                        "status": "vault_not_found",
                    })
                    continue

                st = self.get_storable_by(
                    vault_id=vault.id,
                    internal_id=internal_id,
                )
                if not st:
                    results.append({
                        "internalId": internal_id,
                        "isRecovery": is_recovery,
                        "status": "not_found",
                    })
                    continue

                update_kwargs: Dict[str, Any] = {}
                for json_field, value in changes.items():
                    if json_field not in field_map:
                        continue
                    update_kwargs[field_map[json_field]] = value

                if not update_kwargs:
                    results.append({
                        "internalId": internal_id,
                        "isRecovery": is_recovery,
                        "status": "skipped",
                        "error": "No valid fields to update",
                    })
                    continue

                self.update_storable(st.id, **update_kwargs)
                results.append({
                    "internalId": internal_id,
                    "isRecovery": is_recovery,
                    "status": "updated",
                })

            except Exception as e:
                self.logger.error(
                    f"Error aplicando cambios al storable {internal_id} "
                    f"(is_recovery={is_recovery}): {e}",
                    exc_info=True,
                )
                results.append({
                    "internalId": internal_id,
                    "isRecovery": is_recovery,
                    "status": "error",
                    "error": str(e),
                })

        return results
    
    def delete_storable(self, storable_id: int) -> bool:
        self._check_session()
        st = self.get_storable(storable_id)
        if st is None:
            return False

        try:
            self.session.delete(st)
            self._safe_commit()
            self.logger.info(f"Storable {storable_id} eliminado")
            return True
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error eliminando storable {storable_id}: {e}", exc_info=True)
            raise


class OAuthTokenManager(BaseManager):
    """Gestor de tokens OAuth 2.0 usando JWT"""
    
    def create_access_token(self, user_id: int, username: str) -> str:
        expires_at = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        payload = {
            "sub": str(user_id),
            "username": username,
            "exp": expires_at,
            "iat": datetime.utcnow(),
            "type": "access"
        }
        
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        access_token_record = AccessToken(
            token=token,
            user_id=user_id,
            expires_at=expires_at
        )
        self.session.add(access_token_record)
        self._safe_commit()
        
        return token
    
    def create_refresh_token(self, user_id: int) -> str:
        token = secrets.token_urlsafe(64)
        expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        
        refresh_token_record = RefreshToken(
            token=token,
            user_id=user_id,
            expires_at=expires_at
        )
        self.session.add(refresh_token_record)
        self._safe_commit()
        
        return token
    
    def verify_access_token(self, token: str) -> Optional[dict]:
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
            if payload.get("type") != "access":
                return None
            
            token_record = self.session.query(AccessToken).filter(
                AccessToken.token == token
            ).one_or_none()
            
            if not token_record or not token_record.is_valid():
                return None
            
            return payload
        
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception:
            return None
    
    def verify_refresh_token(self, token: str) -> Optional[int]:
        try:
            token_record = self.session.query(RefreshToken).filter(
                RefreshToken.token == token
            ).one_or_none()
            
            if not token_record or not token_record.is_valid():
                return None
            
            return token_record.user_id # type: ignore
        
        except Exception:
            return None
    
    def revoke_access_token(self, token: str) -> bool:
        try:
            token_record = self.session.query(AccessToken).filter(
                AccessToken.token == token
            ).one_or_none()
            
            if token_record:
                token_record.revoked = 1 # type: ignore
                self._safe_commit()
                return True
            return False
        except Exception:
            return False
    
    def revoke_all_user_tokens(self, user_id: int) -> None:
        try:
            self.session.query(AccessToken).filter(
                AccessToken.user_id == user_id
            ).update({"revoked": 1})
            
            self.session.query(RefreshToken).filter(
                RefreshToken.user_id == user_id
            ).update({"revoked": 1})
            
            self._safe_commit()
        except Exception as e:
            self._safe_rollback()
            raise
    
    def cleanup_expired_tokens(self) -> None:
        try:
            now = datetime.utcnow()
            
            self.session.query(AccessToken).filter(
                AccessToken.expires_at < now
            ).delete()
            
            self.session.query(RefreshToken).filter(
                RefreshToken.expires_at < now
            ).delete()
            
            self._safe_commit()
        except Exception:
            self._safe_rollback()


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class AegisAlert:
    """Representa un aviso de vulnerabilidad recuperado de INCIBE o NVD."""
    title:       str
    description: str
    url:         str
    source:      str           # "incibe" | "nvd"
    published:   str           # ISO-8601 o fecha en texto
    severity:    str = ""      # "crítica" | "alta" | "media" | "baja" | ""
    brands:      list[str] = field(default_factory=list)


# ── Manager ───────────────────────────────────────────────────────────────────

class AegisManager(BaseManager):
    """
    Manager de Aegis: generación asíncrona de píldoras de concienciación
    en ciberseguridad mediante un modelo de IA local (Ollama).
    """

    _INCIBE_AVISOS_FEED  = "https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed"
    _NVD_CVE_API         = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    _MAX_BRANDS          = 5
    _MAX_ALERT_AGE_YEARS = 5

    _FALLBACK_BRANDS: list[str] = [
        "Microsoft", "Google", "Cisco", "Apple", "Adobe",
        "Oracle", "SAP", "VMware", "Fortinet", "Palo Alto",
        "Juniper", "IBM", "Linux", "Android", "Chrome",
    ]

    def __init__(self, user: User, session: Optional[Session] = None):
        super().__init__(session)
        self.user = user
        self.config_reader = ConfigReader()
        self.logger = SecOpsLogger(self.__class__.__name__).get_logger()
        self.alert_fetcher = AegisAlertFetcher(
            logger=self.logger,
            fallback_brands=self._FALLBACK_BRANDS,
        )

    def _read_cfg(self) -> dict[str, Any]:
        aegis = self.config_reader.get_aegis_config()
        ol    = aegis.get("ollama", {}) or {}
        paths = aegis.get("paths",  {}) or {}

        api_root   = Path(__file__).resolve().parents[2]
        stack_dir  = api_root / str(paths.get("stackDir",  "data/aegis/stack"))
        output_dir = api_root / str(paths.get("outputDir", "data/aegis/output"))
        output_dir.mkdir(parents=True, exist_ok=True)

        return {
            "enabled":         bool(aegis.get("enabled", True)),
            "ollama_host":     str(ol.get("host",           "http://localhost:11434")),
            "ollama_model":    str(ol.get("model",          "mistral")),
            "timeout_seconds": int(ol.get("timeoutSeconds", 120)),
            "stack_dir":       stack_dir,
            "output_dir":      output_dir,
        }

    def _get_topic_from_db(
        self, topic_id: Optional[int]
    ) -> tuple[Optional[Topic], bool]:
        if topic_id is not None:
            topic = (
                self.session.query(Topic)
                .filter(Topic.id == topic_id)
                .first()
            )
            if topic:
                return topic, False
            self.logger.warning(
                f"Topic id={topic_id} no encontrado en BD. Se usará uno aleatorio."
            )

        all_topics = self.session.query(Topic).all()
        if not all_topics:
            return None, False

        return random.choice(all_topics), True

    def _load_reference_stack(self, stack_dir: Path) -> str:
        if not stack_dir.exists():
            return ""
        files = sorted(
            stack_dir.glob("*.md"),
            key=lambda p: p.stat().st_mtime
        )
        if not files:
            return ""
        return "\n\n---\n\n".join(
            p.read_text(encoding="utf-8") for p in files[-3:]
        )
 
    def _create_pending_document(self, topic_id: int) -> int:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        placeholder = f"pending_{ts}_{self.user.id}_{topic_id}"

        doc = AegisDocument(
            title=placeholder[:64],
            filename=f"{placeholder}.md"[:128],
            status="pending",
            topic_id=topic_id,
            user_id=self.user.id,
        )
        self.session.add(doc)
        self.session.flush()
        self._safe_commit()
        return doc.id

    def _update_document(
        self,
        document_id: int,
        status: str,
        title: str | None = None,
        filename: str | None = None,
        error: str | None = None,
    ) -> None:
        doc = self.session.get(AegisDocument, document_id)
        if not doc:
            self.logger.error(f"Aegis _update_document: doc {document_id} no encontrado")
            return

        doc.status = status

        if title:
            doc.title = title[:64]

        if filename:
            doc.filename = filename[:128]

        if error and status == "error":
            doc.title = f"[ERROR] {error}"[:64]

        self._safe_commit()

    def _run_generate(self, document_id: int, topic_id: int, tweaks: dict) -> None:
        try:
            cfg = self._read_cfg()

            pill_content = self._generate_content(topic_id, tweaks, cfg)

            alerts = self.alert_fetcher.fetch_alerts(
                brands=tweaks.get("associatedBrands", []),
                max_per_brand=2,
                timeout=10,
            )

            full_body = (
                pill_content.body
                + "\n\n"
                + self.alert_fetcher.alerts_to_markdown(alerts)
            )

            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"{ts}_{self.user.id}_{topic_id}.md"
            cfg_out = cfg["output_dir"]
            path = cfg_out / filename

            with path.open("w", encoding="utf-8") as f:
                f.write(full_body)

            self._update_document(
                document_id=document_id,
                status="done",
                title=pill_content.topic_title,
                filename=filename,
            )
            self.logger.info(f"Aegis: '{filename}' generado (id={document_id})")

        except Exception as e:
            self.logger.error(
                f"Aegis _run_generate: error en doc {document_id}: {e}",
                exc_info=True,
            )
            try:
                self._update_document(
                    document_id=document_id,
                    status="error",
                    error=str(e),
                )
            except Exception as update_err:
                self.logger.error(
                    f"Aegis _run_generate: error actualizando estado de doc "
                    f"{document_id}: {update_err}",
                    exc_info=True,
                )

        finally:
            self.close_session()
    
    def _generate_content(
        self,
        topic_id: Optional[int],
        tweaks: dict[str, Any],
        cfg: dict[str, Any],
    ) -> AegisContent:
        if not cfg["enabled"]:
            raise RuntimeError("Aegis está deshabilitado por configuración")

        topic, was_random = self._get_topic_from_db(topic_id)

        if topic is None:
            topic_note = "No hay topics en BD. Contenido genérico generado."
            resolved_topic_id = topic_id or 0
            topic_title = tweaks.get("topicFocus") or "Ciberseguridad general"
        elif was_random:
            topic_note = (
                f"Topic solicitado no encontrado. "
                f"Se usó uno aleatorio: '{topic.title}' (id={topic.id})."
            )
            resolved_topic_id = topic.id
            topic_title = topic.title
        else:
            topic_note = ""
            resolved_topic_id = topic.id
            topic_title = topic.title

        if topic_note:
            self.logger.info(f"Aegis topic note: {topic_note}")

        reference = self._load_reference_stack(cfg["stack_dir"])

        writer = AegisAIWriter(
            host=cfg["ollama_host"],
            model=cfg["ollama_model"],
            logger=self.logger,
        )

        return writer.generate_pill(
            topic=topic,
            resolved_topic_id=resolved_topic_id,
            topic_title=topic_title,
            topic_note=topic_note,
            reference=reference,
            tweaks=tweaks,
        )

    def list_documents(self) -> list[dict[str, Any]]:
        docs = (
            self.session.query(AegisDocument)
            .filter(AegisDocument.user_id == self.user.id)
            .order_by(AegisDocument.generated_at.desc())
            .all()
        )
        return [
            {
                "id":          d.id,
                "title":       d.title,
                "filename":    d.filename,
                "generatedAt": d.generated_at.isoformat(),
            }
            for d in docs
        ]

    def get_document_path(self, document_id: int) -> Path:
        doc = (
            self.session.query(AegisDocument)
            .filter(
                AegisDocument.id      == document_id,
                AegisDocument.user_id == self.user.id,
            )
            .first()
        )
        if not doc:
            raise ValueError(
                f"Documento {document_id} no encontrado o no pertenece al usuario"
            )
        cfg  = self._read_cfg()
        path = cfg["output_dir"] / doc.filename
        if not path.exists():
            raise FileNotFoundError(
                f"El fichero '{doc.filename}' no existe en disco. "
                "Es posible que haya sido eliminado manualmente."
            )
        return path

    def delete_document(self, document_id: int) -> None:
        doc = (
            self.session.query(AegisDocument)
            .filter(
                AegisDocument.id      == document_id,
                AegisDocument.user_id == self.user.id,
            )
            .first()
        )
        if not doc:
            raise ValueError(
                f"Documento {document_id} no encontrado o no pertenece al usuario"
            )
        cfg  = self._read_cfg()
        path = cfg["output_dir"] / doc.filename
        if path.exists():
            os.remove(path)
            self.logger.info(f"Aegis: fichero eliminado → {path}")
        else:
            self.logger.warning(
                f"Aegis: '{doc.filename}' no encontrado en disco al eliminar"
            )
        self.session.delete(doc)
        self.session.commit()
        self.logger.info(f"Aegis: documento id={document_id} eliminado de BD")

    def get_document(self, document_id: int) -> dict | None:
        cfg = self._read_cfg()
        output_dir = cfg["output_dir"]
        doc = self.session.get(AegisDocument, document_id)
        if not doc:
            return None

        result = {
            "id":          doc.id,
            "title":       doc.title,
            "filename":    doc.filename,
            "status":      doc.status,
            "generatedAt": doc.generated_at.isoformat(),
            "topicId":     doc.topic_id,
            "userId":      doc.user_id,
            "content":     None,
        }

        if doc.status == "done":
            try:
                path = os.path.join(output_dir, doc.filename)
                with open(path, "r", encoding="utf-8") as f:
                    result["content"] = f.read()
            except FileNotFoundError:
                self.logger.warning(f"Aegis get_document: fichero no encontrado: {doc.filename}")

        return result

    def generate(
        self,
        topic_id: int,
        tweaks: Optional[dict[str, Any]] = None,
    ) -> int:
        tweaks = tweaks or {}

        document_id = self._create_pending_document(topic_id)
        thread_manager = self.__class__(self.user)

        thread = threading.Thread(
            target=thread_manager._run_generate,
            args=(document_id, topic_id, tweaks),
            daemon=True,  # fix: daemon=True para no bloquear shutdown
            name=f"Aegis-{document_id}",
        )
        thread.start()

        return document_id
