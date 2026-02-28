# Standard library
import secrets
import threading
import time
from pathlib import Path
import urllib.parse
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Iterable

from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional, Dict
import time


# Third party
import jwt

# SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from pymysql.err import IntegrityError

# Local imports
from src.core.exceptions import ExistingUserError, UserBindingError, DatabaseError
from src.core.model import (
    AccessToken,
    NiktoScan,
    NmapScan,
    Person,
    RefreshToken,
    Scan,
    User,
    OpenVASScan,
    Vault,
    Storable,
    Account,
    CreditCard
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
            # Obtener credenciales por defecto
            (USERNAME, PASSWORD, HOST, DBNAME) = ConfigReader().get_db_crendetials()
            database_url = (
                f"mysql+pymysql://{USERNAME}:{urllib.parse.quote(PASSWORD)}@{HOST}/{DBNAME}"
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
        """
        Args:
            session: Sesión SQLAlchemy externa opcional. 
                     Si es None, usa la sesión del thread actual.
        """
        global _SESSION_FACTORY
        
        # Inicializar engine si no existe
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
        """Verifica que la sesión está activa"""
        if self.session is None:
            raise Exception("La sesión de base de datos no está establecida.")
    
    def close_session(self):
        """Cierra la sesión del thread actual si fue creada por este manager"""
        if self._owns_session and self.session is not None:
            try:
                self.session.close()
                _SESSION_FACTORY.remove() # type: ignore
            except Exception as e:
                self.logger.warning(f"Error al cerrar sesión: {e}")
    
    def _safe_commit(self):
        """Realiza un commit seguro con manejo de errores"""
        try:
            self.session.commit()
            return True
        except SQLAlchemyError as err:
            self.logger.error(f"Error durante commit: {err}")
            self._safe_rollback()
            raise
    
    def _safe_rollback(self):
        """Realiza un rollback seguro"""
        try:
            if self.session is not None:
                self.session.rollback()
                self.logger.debug("Rollback ejecutado exitosamente")
        except Exception as e:
            self.logger.warning(f"Error durante rollback: {e}")
            # Intentar recrear sesión si falla
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
        """Cierra todas las sesiones y limpia el factory"""
        global _SESSION_FACTORY
        if _SESSION_FACTORY is not None:
            _SESSION_FACTORY.remove()


class ScanManager(BaseManager, ABC):
    """
    Clase base para gestores de escaneos.
    Responsabilidad: Coordinar la ejecución de tareas y la persistencia de resultados.
    """

    _running_tasks: Dict[int, _Task] = {}
    _running_tasks_lock = threading.RLock()

    def __init__(self, user: User, session: Optional[Session] = None):
        super().__init__(session)
        self.active_user = user

    # ------------ Helpers de clase para el registro global ------------

    @classmethod
    def _register_task(cls, scan_id: int, task: _Task) -> None:
        with cls._running_tasks_lock:
            cls._running_tasks[scan_id] = task

    @classmethod
    def _get_task(cls, scan_id: int) -> Optional[_Task]:
        with cls._running_tasks_lock:
            return cls._running_tasks.get(scan_id)

    @classmethod
    def _unregister_task(cls, scan_id: int) -> None:
        with cls._running_tasks_lock:
            cls._running_tasks.pop(scan_id, None)
    
    def get_scan_by_id(self, scan_id: int) -> Optional[Scan]:
        """Obtiene un escaneo por ID"""
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
        """Obtiene todos los escaneos del usuario activo"""
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
        """Elimina un escaneo"""
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
        """Obtiene el progreso de un escaneo en ejecución"""
        task = self._get_task(scan_id)
        if task:
            progress = task.progress
            self.logger.debug(f"Progreso de escaneo {scan_id}: {progress}%")
            return progress
        return None
    
    def get_scan_status(self, scan_id: int) -> Optional[str]:
        """Obtiene el estado de un escaneo"""
        task = self._get_task(scan_id)
        if task:
            return str(task.status)
        if self._is_scan_finished(scan_id):
            return str(TaskStatus.COMPLETED)
        return None
    
    def is_scan_finished(self, scan_id: int) -> Optional[bool]:
        """Verifica si un escaneo ha finalizado"""
        return self._is_scan_finished(scan_id)
    
    def cancel_scan(self, scan_id: int) -> bool:
        """
        Cancela un escaneo en ejecución.
        
        Validaciones:
        - Verifica que el escaneo existe
        - Verifica que pertenece al usuario activo
        - Solo permite cancelar escaneos en estado 'pending' o 'running'
        
        Args:
            scan_id: ID del escaneo a cancelar
        
        Returns:
            bool: True si se canceló correctamente, False en caso contrario
        """
        try:
            # Verificar que el escaneo existe
            scan = self.get_scan_by_id(scan_id)
            if not scan:
                self.logger.warning(f"Escaneo {scan_id} no encontrado, no se puede cancelar")
                return False
            
            # Verificar que el escaneo pertenece al usuario activo
            if scan.user_id != self.active_user.id:
                self.logger.warning(
                    f"El usuario {self.active_user.username} no tiene permisos para cancelar el escaneo {scan_id}"
                )
                return False
            
            # Verificar que el escaneo está en un estado cancelable
            if scan.status not in ['pending', 'running']:
                self.logger.warning(
                    f"El escaneo {scan_id} no se puede cancelar (estado actual: {scan.status})"
                )
                return False
            
            # Intentar cancelar la tarea en ejecución
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
            
            # Actualizar estado en la base de datos
            self._update_scan_status(scan_id, 'cancelled')
            
            self.logger.info(f"Escaneo {scan_id} cancelado exitosamente")
            return True
        
        except Exception as e:
            self.logger.error(f"Error cancelando escaneo {scan_id}: {e}", exc_info=True)
            return False
    

    @abstractmethod
    def run_scan(self, **kwargs) -> int:
        """
        Inicia un nuevo escaneo.
        Retorna: ID del escaneo creado
        """
        pass
    
    @abstractmethod
    def _create_scan_record(self, **kwargs) -> Scan:
        """Crea el registro inicial del escaneo en BD"""
        pass
    
    @abstractmethod
    def _create_task(self, **kwargs) -> _Task:
        """Crea la tarea específica de escaneo"""
        pass
    
    @abstractmethod
    def _get_result_processor(self) -> ScanResultProcessor:
        """Retorna el procesador de resultados apropiado"""
        pass
    
    # --- Métodos compartidos (implementación común) ---
    
    def _execute_scan_in_thread(self, scan_id: int, task: _Task) -> None:
        """
        Ejecuta un escaneo en un thread separado.
        Patrón común para todos los tipos de escaneo.
        """
        # Crear manager con sesión independiente para este thread
        thread_manager = self.__class__(self.active_user)
        
        try:
            scan = thread_manager.get_scan_by_id(scan_id)
            if not scan:
                thread_manager.logger.error(f"Escaneo {scan_id} no encontrado")
                return
            
            thread_manager.logger.info(f"Iniciando escaneo {scan_id}")
            
            self._register_task(scan_id, task)

            # Ejecutar escaneo
            task.scan()
            success = task.wait(timeout=task.timeout + 30)
            
            if not success or task.results is None:
                thread_manager.logger.error(
                    f"Escaneo {scan_id} falló. Estado: {task.status}"
                )
                thread_manager._mark_scan_as_failed(scan)
                return
            
            scan.status = "finished"
            
            # Procesar y guardar resultados
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
        """Marca un escaneo como fallido"""
        scan.ended_at = datetime.now()
        self.session.add(scan)
        self._safe_commit()
    
    def _is_scan_finished(self, scan_id: int) -> bool:
        """Verifica si un escaneo está finalizado"""
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
        """
        Actualiza el estado de un escaneo en la base de datos.
        
        Args:
            scan_id: ID del escaneo
            status: Nuevo estado ('pending', 'running', 'completed', 'failed', 'cancelled')
        
        Returns:
            bool: True si se actualizó correctamente, False en caso contrario
        """
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
        """
        Configura callbacks para actualizar el estado cuando la tarea finalice.
        
        Args:
            task: Tarea a la que añadir el callback
            scan_id: ID del escaneo asociado
        """
        original_wait = task.wait
        
        def wait_with_callback(timeout: Optional[float] = None) -> bool:
            """Wrapper de wait que actualiza el estado al finalizar"""
            result = original_wait(timeout)
            
            try:
                # Actualizar estado según el resultado
                if task.status == TaskStatus.COMPLETED:
                    self._update_scan_status(scan_id, 'completed')
                elif task.status == TaskStatus.FAILED:
                    self._update_scan_status(scan_id, 'failed')
                elif task.status == TaskStatus.CANCELLED:
                    self._update_scan_status(scan_id, 'cancelled')
                elif task.status == TaskStatus.TIMEOUT:
                    self._update_scan_status(scan_id, 'failed')
                
                # Eliminar de tareas en ejecución
                if scan_id in self.running_tasks:
                    del self.running_tasks[scan_id]
            
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
        self.hostname = config["hostname"]
        self.port = config["port"]
        self.username = config["username"]
        self.password = config["password"]
    
    def run_scan(self, target: str, scan_config: str = 'full_fast') -> int:
        """Inicia un escaneo OpenVAS"""
        try:
            target_ip, _ = normalize_target(target)
            config_id = self.SCAN_CONFIGS.get(scan_config, self.SCAN_CONFIGS['full_fast'])
            
            # Crear registro en BD
            scan = self._create_scan_record(target=target_ip)
            scan_id = scan.id
            
            # Crear tarea
            task = self._create_task(
                target=target_ip,
                scan_config=config_id,
                timeout=30000000
            )
            
            # Ejecutar en thread
            thread = threading.Thread(
                target=self._execute_scan_in_thread,
                args=(scan_id, task),
                daemon=False,
                name=f"OpenVASScan-{scan_id}"
            )
            thread.start()
            time.sleep(0.2)

            self._register_task(scan_id, task)
            
            self.logger.info(f"Escaneo OpenVAS {scan_id} iniciado")
            return scan_id
        
        except Exception as e:
            self.logger.error(f"Error iniciando escaneo OpenVAS: {e}", exc_info=True)
            raise
    
    def _create_scan_record(self, target: str) -> OpenVASScan:
        """Crea el registro del escaneo OpenVAS con ID temporal único"""
        import uuid
        
        # Generar ID temporal único (36 caracteres)
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
        """Crea la tarea de escaneo OpenVAS"""
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
        """Retorna el procesador de resultados OpenVAS"""
        return OpenVASResultProcessor(self.session, self.logger)
    
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
            
            # Registrar tarea
            self._register_task(scan_id, task)
            
            # Ejecutar escaneo
            task.scan()
            success = task.wait(timeout=task.timeout + 30)
            
            if not success or task.results is None:
                thread_manager.logger.error(
                    f"Escaneo {scan_id} falló. Estado: {task.status}"
                )
                thread_manager._mark_scan_as_failed(scan)
                return
            
            # Actualizar IDs de OpenVAS
            scan.task_id = task.task_id
            scan.report_id = task.report_id
            thread_manager.session.add(scan)
            
            # Procesar y guardar resultados
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
            if scan_id in self.running_tasks:
                del self.running_tasks[scan_id]


class NmapScanManager(ScanManager):
    """Gestor de escaneos Nmap"""
    
    def run_scan(self, target_host: str, target_ports: str, timeout: int = 120) -> int:
        """Inicia un escaneo Nmap"""
        try:
            # Crear registro en BD
            scan = self._create_scan_record(target=target_host)
            scan_id = scan.id
            
            # Crear tarea
            task = self._create_task(
                target_host=target_host,
                target_ports=target_ports,
                timeout=timeout
            )
            
            # Ejecutar en thread
            thread = threading.Thread(
                target=self._execute_scan_in_thread,
                args=(scan_id, task),
                daemon=False,
                name=f"NmapScan-{scan_id}"
            )

            self._register_task(scan_id, task)

            thread.start()
            time.sleep(0.2)
            
            self.logger.info(f"Escaneo Nmap {scan_id} iniciado")
            return scan_id
        
        except Exception as e:
            self.logger.error(f"Error iniciando escaneo Nmap: {e}", exc_info=True)
            raise
    
    def _create_scan_record(self, target: str) -> NmapScan:
        """Crea el registro del escaneo Nmap"""
        scan = NmapScan(
            target=target,
            user=self.active_user,
            started_at=datetime.now()
        )
        self.session.add(scan)
        self._safe_commit()
        return scan
    
    def _create_task(self, target_host: str, target_ports: str, timeout: int) -> NmapScanTask:
        """Crea la tarea de escaneo Nmap"""
        return NmapScanTask(target_host, target_ports, timeout)
    
    def _get_result_processor(self) -> NmapResultProcessor:
        """Retorna el procesador de resultados Nmap"""
        return NmapResultProcessor(self.session, self.logger)


class NiktoScanManager(ScanManager):
    """Gestor de escaneos Nikto"""
    
    def run_scan(self, target_domain: str, timeout: int = 60) -> int:
        """Inicia un escaneo Nikto"""
        try:
            # Crear registro en BD
            scan = self._create_scan_record(target=target_domain)
            scan_id = scan.id
            
            # Crear tarea
            task = self._create_task(target_domain=target_domain, timeout=timeout)
            
            # Ejecutar en thread
            thread = threading.Thread(
                target=self._execute_scan_in_thread,
                args=(scan_id, task),
                daemon=False,
                name=f"NiktoScan-{scan_id}"
            )
            thread.start()
            time.sleep(0.2)

            self._register_task(scan_id, task)
            
            self.logger.info(f"Escaneo Nikto {scan_id} iniciado")
            return scan_id
        
        except Exception as e:
            self.logger.error(f"Error iniciando escaneo Nikto: {e}", exc_info=True)
            raise
    
    def _create_scan_record(self, target: str) -> NiktoScan:
        """Crea el registro del escaneo Nikto"""
        scan = NiktoScan(
            target=target,
            user=self.active_user,
            started_at=datetime.now()
        )
        self.session.add(scan)
        self._safe_commit()
        return scan
    
    def _create_task(self, target_domain: str, timeout: int) -> NiktoScanTask:
        """Crea la tarea de escaneo Nikto"""
        return NiktoScanTask(target_domain, timeout)
    
    def _get_result_processor(self) -> NiktoResultProcessor:
        """Retorna el procesador de resultados Nikto"""
        return NiktoResultProcessor(self.session, self.logger)


class UserManager(BaseManager):
    """
    Gestor completo para usuarios y personas con autenticación y gestión de tokens.
    
    Características:
        - Autenticación con salt y hash
        - Gestión de usuarios y personas
        - Validación de credenciales
        - CRUD completo thread-safe
    """
    
    def verify_credentials(self, username: str, password: str) -> Tuple[bool, Optional[int]]:
        """
        Verifica las credenciales de un usuario.
        
        Args:
            username (str): Nombre de usuario
            password (str): Contraseña en texto plano
        
        Returns:
            Tuple[bool, Optional[int]]: (es_válido, user_id)
        """
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
        """Validación simple de credenciales sin devolver user_id."""
        is_valid, _ = self.verify_credentials(username, password)
        return is_valid
    
    def create_user(self, user: User) -> None:
        """
        Crea un nuevo usuario.
        
        Args:
            user (User): Usuario a crear
        
        Raises:
            ExistingUserError: Si el usuario ya existe
        """
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
        """
        Registra un nuevo usuario vinculándolo a una persona.
        
        Args:
            username (str): Nombre de usuario
            password (str): Contraseña en texto plano
            email (str): Email del usuario
            alias (str): Alias de la persona existente
        
        Returns:
            User: Usuario creado
        
        Raises:
            ExistingUserError: Si el usuario ya existe
            UserBindingError: Si no existe la persona
        """
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
        """Obtiene un usuario por su username."""
        return self._get_by_field(User, "username", username)
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Obtiene un usuario por ID."""
        return self._get_by_field(User, "id", user_id)
    
    def get_all_users(self) -> List[User]:
        """Obtiene todos los usuarios."""
        return self._get_all(User)
    
    def update_user_password(self, user: User, new_password: str) -> None:
        """
        Actualiza la contraseña de un usuario.
        
        Args:
            user (User): Usuario a actualizar
            new_password (str): Nueva contraseña
        """
        self._check_session()
        
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
        """Actualiza la contraseña de un usuario por ID."""
        user = self.get_user_by_id(user_id)
        
        if not user:
            raise UserBindingError(username=str(user_id), alias="unknown")
        
        self.update_user_password(user, new_password)
    
    def delete_user(self, user: User) -> None:
        """Elimina un usuario."""
        self._delete(user, "Usuario")
    
    def sign_in_person(self, first_name: str, last_name: str, alias: str) -> Person:
        """
        Registra una nueva persona.
        
        Args:
            first_name (str): Nombre
            last_name (str): Apellido
            alias (str): Alias único
        
        Returns:
            Person: Persona creada
        
        Raises:
            ExistingUserError: Si ya existe
        """
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
        """Obtiene una persona por alias."""
        return self._get_by_field(Person, "alias", alias)
    
    def get_person_by_email(self, email: str) -> Optional[Person]:
        """Obtiene una persona por email."""
        return self._get_by_field(Person, "email", email)
    
    def get_person_by_id(self, person_id: int) -> Optional[Person]:
        """Obtiene una persona por ID."""
        return self._get_by_field(Person, "id", person_id)
    
    def get_all_people(self) -> List[Person]:
        """Obtiene todas las personas."""
        return self._get_all(Person)
    
    def update_person(self, person: Person) -> None:
        """Actualiza la información de una persona."""
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
        """Elimina una persona."""
        self._delete(person, "Persona")
    
    # Métodos privados genéricos
    
    def _get_by_field(self, model, field: str, value: Any) -> Optional[Any]:
        """
        Obtiene un objeto por un campo específico.
        
        Args:
            model: Clase del modelo
            field (str): Nombre del campo
            value: Valor a buscar
        
        Returns:
            Optional[Any]: Objeto encontrado o None
        """
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
        """Obtiene todos los objetos de un modelo."""
        self._check_session()
        
        try:
            objects = self.session.query(model).all()
            self.logger.info(f"Se obtuvieron {len(objects)} {model.__name__}s")
            return objects
        
        except Exception as e:
            self.logger.error(f"Error obteniendo {model.__name__}s: {e}")
            raise
    
    def _exists(self, model, field: str, value: Any) -> bool:
        """Verifica si existe un objeto con el campo especificado."""
        self._check_session()
        
        exists = self.session.query(model).filter(
            getattr(model, field) == value
        ).count() > 0
        
        return exists
    
    def _delete(self, obj: Any, obj_type: str) -> None:
        """
        Elimina un objeto genérico.
        
        Args:
            obj: Objeto a eliminar
            obj_type (str): Tipo de objeto (para logging)
        """
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
        """Crea una nueva persona (método interno)."""
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

    Responsabilidades:
      - Crear/actualizar vaults a partir de JSON.
      - Exportar vaults a JSON.
      - Listar y modificar Storables (Account / CreditCard).
      - Garantizar que solo el usuario dueño del vault lo manipula.
    """

    def __init__(self, user: User, session: Optional[Session] = None):
        super().__init__(session)
        self.active_user = user

    # ----------------- Helpers internos -----------------

    @staticmethod
    def _parse_dt(value: Optional[str]) -> datetime:
        """
        Convierte un string ISO8601 a datetime. Si es None o falla, usa ahora.
        """
        if not value:
            return datetime.utcnow()
        try:
            # Python 3.11: soporta offsets tipo "+01:00"
            return datetime.fromisoformat(value)
        except Exception:
            return datetime.utcnow()

    def _ensure_vault_ownership(self, vault: Vault) -> None:
        if vault.user_id != self.active_user.id:
            raise PermissionError(
                f"El usuario {self.active_user.id} no es dueño del vault {vault.id}"
            )

    # ----------------- Operaciones sobre Vault -----------------

    def get_vault_by_id(self, vault_id: int) -> Optional[Vault]:
        """
        Obtiene un vault por ID, verificando que pertenece al usuario activo.
        """
        self._check_session()
        vault = self.session.get(Vault, vault_id)
        if vault is None:
            self.logger.warning(f"Vault {vault_id} no encontrado")
            return None
        self._ensure_vault_ownership(vault)
        return vault

    def get_vault_for_user(self, is_recovery: bool = False) -> Optional[Vault]:
        """
        Devuelve el vault del usuario (normal o de recuperación).
        """
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

    def create_vault_from_json(
        self,
        data: Dict[str, Any],
        is_recovery: bool = False,
    ) -> Vault:
        """
        Crea un nuevo vault para el usuario activo a partir de un JSON
        con la estructura del ejemplo (checker, vaultKey, algorithm, accounts, creditcards).

        No hace "upsert": si ya existe un vault (user_id, is_recovery) la BD
        lanzará un error de unicidad que se propaga.
        """
        self._check_session()

        try:
            algorithm = data.get("algorithm", {}) or {}

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
            self.session.flush()  # para tener vault.id

            # Accounts
            for acc in data.get("accounts", []) or []:
                created = self._parse_dt(acc.get("createdAt"))
                updated = self._parse_dt(acc.get("updatedAt"))

                account = Account(
                    vault=vault,
                    internal_id=acc.get("id"),
                    title=acc.get("title"),
                    created_at=created,
                    updated_at=updated,
                    username=acc.get("username", ""),
                    domain=acc.get("domain", ""),
                    password=acc.get("password", ""),
                )
                self.session.add(account)

            # Credit cards
            for card in data.get("creditcards", []) or []:
                created = self._parse_dt(card.get("createdAt"))
                updated = self._parse_dt(card.get("updatedAt"))

                cc = CreditCard(
                    vault=vault,
                    internal_id=card.get("id"),
                    title=card.get("title"),
                    created_at=created,
                    updated_at=updated,
                    cardholder_name=card.get("cardHolderName", ""),
                    card_number=card.get("cardNumber", ""),
                    expiration_date=card.get("expirationDate", ""),
                    postal_code=card.get("postalCode", ""),
                    cvv=card.get("cvv", ""),
                )
                self.session.add(cc)

            self._safe_commit()
            self.session.refresh(vault)
            self.logger.info(f"Vault {vault.id} creado para user {self.active_user.id}")
            return vault

        except IntegrityError as ie:
            self._safe_rollback()
            self.logger.error(f"Error de integridad creando vault: {ie}")
            raise
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error creando vault desde JSON: {e}", exc_info=True)
            raise

    def export_vault_to_json(self, vault_id: int) -> Dict[str, Any]:
        """
        Convierte un vault y sus storables a un dict JSON con el formato del ejemplo.

        Lanza:
          - ValueError si el vault no existe o no pertenece al usuario.
        """
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

        # SQLAlchemy ya te cargará subclases por polimorfismo
        for st in vault.storables:
            base = {
                "id": st.internal_id,
                "title": st.title,
                "createdAt": st.created_at.isoformat() if st.created_at else None,
                "updatedAt": st.updated_at.isoformat() if st.updated_at else None,
                "allowedUsers": [],  # aún no implementado
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

    # ----------------- Operaciones sobre Storables -----------------

    def list_storables(self, vault_id: int) -> List[Storable]:
        """
        Devuelve todos los storables de un vault del usuario activo.
        """
        vault = self.get_vault_by_id(vault_id)
        if vault is None:
            return []
        # storables ya está filtrado por vault
        return list(vault.storables)

    def get_storable(self, storable_id: int) -> Optional[Storable]:
        """
        Obtiene un Storable (Account / CreditCard) asegurando que pertenece 
        a un vault del usuario activo.
        """
        self._check_session()
        st = self.session.get(Storable, storable_id)
        if st is None:
            return None
        if st.vault.user_id != self.active_user.id:
            raise PermissionError(
                f"El usuario {self.active_user.id} no tiene acceso al storable {storable_id}"
            )
        return st

    def update_storable(
        self,
        storable_id: int,
        *,
        title: Optional[str] = None,
        internal_id: Optional[str] = None,
        # campos específicos de Account
        username: Optional[str] = None,
        domain: Optional[str] = None,
        password: Optional[str] = None,
        # campos específicos de CreditCard
        cardholder_name: Optional[str] = None,
        card_number: Optional[str] = None,
        expiration_date: Optional[str] = None,
        postal_code: Optional[str] = None,
        cvv: Optional[str] = None,
    ) -> Storable:
        """
        Actualiza campos de un Storable (y de su subtipo si aplica).

        Solo permite modificar campos explícitos; cualquier parámetro None se ignora.
        """
        self._check_session()
        st = self.get_storable(storable_id)
        if st is None:
            raise ValueError(f"Storable {storable_id} no encontrado")

        try:
            # Campos base
            changed = False
            if title is not None:
                st.title = title
                changed = True
            if internal_id is not None:
                st.internal_id = internal_id
                changed = True

            # Campos de Account
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

            # Campos de CreditCard
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

    def delete_storable(self, storable_id: int) -> bool:
        """
        Elimina un storable (y su subtabla asociada) si pertenece al usuario activo.
        """
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
        """Crea un JWT access token"""
        expires_at = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        payload = {
            "sub": str(user_id),  # subject (user ID)
            "username": username,
            "exp": expires_at,  # expiration time
            "iat": datetime.utcnow(),  # issued at
            "type": "access"
        }
        
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        # Guardar en DB
        access_token_record = AccessToken(
            token=token,
            user_id=user_id,
            expires_at=expires_at
        )
        self.session.add(access_token_record)
        self._safe_commit()
        
        return token
    
    def create_refresh_token(self, user_id: int) -> str:
        """Crea un refresh token opaco (no JWT)"""
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
        """
        Verifica y decodifica un access token.
        Returns: Payload del token si es válido, None si no lo es
        """
        try:
            # Decodificar JWT
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
            # Verificar tipo
            if payload.get("type") != "access":
                return None
            
            # Verificar si está revocado en DB
            token_record = self.session.query(AccessToken).filter(
                AccessToken.token == token
            ).one_or_none()
            
            if not token_record or not token_record.is_valid():
                return None
            
            return payload
        
        except jwt.ExpiredSignatureError:
            return None  # Token expirado
        except jwt.InvalidTokenError:
            return None  # Token inválido
        except Exception as e:
            return None
    
    def verify_refresh_token(self, token: str) -> Optional[int]:
        """
        Verifica un refresh token.
        Returns: user_id si es válido, None si no lo es
        """
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
        """Revoca un access token"""
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
        """Revoca todos los tokens de un usuario"""
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
        """Elimina tokens expirados de la DB (ejecutar periódicamente)"""
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