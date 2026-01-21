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

from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional, Dict
import time


# Third party
import jwt

# SQLAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from pymysql.err import IntegrityError

# Local imports
from src.core.exceptions import ExistingUserError, UserBindingError, DatabaseError
from src.core.model import (
    AccessToken,
    FinishedScan,
    NiktoIncident,
    NiktoScan,
    NmapScan,
    OpenPort,
    Person,
    Port,
    RefreshToken,
    Scan,
    User,
    Host,
    OpenVASScan,
    OpenVASVulnerability,
    OpenVASScanResult
)
from src.logic.secrets import Encoder
from src.logic.tasks import NmapScanTask, NiktoScanTask, TaskStatus, _Task, OpenVASTask
from src.misc.configread import ConfigReader
from src.misc.conversion import JSONManager
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
    
    def __init__(self, user: User, session: Optional[Session] = None):
        super().__init__(session)
        self.active_user = user
        self.running_tasks: Dict[int, _Task] = {}
    
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
        if scan_id in self.running_tasks:
            progress = self.running_tasks[scan_id].progress
            self.logger.debug(f"Progreso de escaneo {scan_id}: {progress}%")
            return progress
        
        return None
    
    def get_scan_status(self, scan_id: int) -> Optional[str]:
        """Obtiene el estado de un escaneo"""
        if scan_id in self.running_tasks:
            status = self.running_tasks[scan_id].status
            return str(status)
        
        if self._is_scan_finished(scan_id):
            return str(TaskStatus.COMPLETED)
        
        return None
    
    def is_scan_finished(self, scan_id: int) -> Optional[bool]:
        """Verifica si un escaneo ha finalizado"""
        return self._is_scan_finished(scan_id)
    
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
            
            # Registrar tarea
            self.running_tasks[scan_id] = task
            
            # Ejecutar escaneo
            task.scan()
            success = task.wait(timeout=task.timeout + 30)
            
            if not success or task.results is None:
                thread_manager.logger.error(
                    f"Escaneo {scan_id} falló. Estado: {task.status}"
                )
                thread_manager._mark_scan_as_failed(scan)
                return
            
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
            if scan_id in self.running_tasks:
                del self.running_tasks[scan_id]
    
    def _mark_scan_as_failed(self, scan: Scan) -> None:
        """Marca un escaneo como fallido"""
        scan.ended_at = datetime.now()
        self.session.add(scan)
        self._safe_commit()
    
    def _is_scan_finished(self, scan_id: int) -> bool:
        """Verifica si un escaneo está finalizado"""
        try:
            self._check_session()
            count = self.session.query(FinishedScan).filter(
                FinishedScan.id == scan_id
            ).count()
            return count > 0
        
        except Exception as e:
            self.logger.error(f"Error verificando estado: {e}")
            return False


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
            self.running_tasks[scan_id] = task
            
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