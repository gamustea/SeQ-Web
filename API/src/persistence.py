from sqlalchemy import text, create_engine
from sqlalchemy.orm import sessionmaker, Session, scoped_session
from sqlalchemy.exc import SQLAlchemyError
from typing import List, Optional
from abc import ABC, abstractmethod
import urllib.parse

from src.misc.logging import SecOpsLogger
from src.core.model import (
    Person,
    User,
    Scan,
    Port,
    OpenPort,
    NmapScan,
    NiktoIncident,
    NiktoScan,
    FinishedScan,
)
from src.misc.configread import ConfigReader
from datetime import datetime

# Obtener credenciales para la conexión a la base de datos y construir la URL de conexión MySQL
(USERNAME, PASSWORD, HOST, DBNAME) = ConfigReader().get_db_crendetials()
DEFAULT_DATABASE_URL = (
    f"mysql+pymysql://{USERNAME}:{urllib.parse.quote(PASSWORD)}@{HOST}/{DBNAME}"
)

# Variables globales para gestión de sesiones thread-safe
_ENGINE = None
_SESSION_FACTORY = None


def initialize_engine(database_url: str = DEFAULT_DATABASE_URL):
    """
    Inicializa el engine y el session factory una sola vez.
    Debe ser llamado al inicio de la aplicación.
    """
    global _ENGINE, _SESSION_FACTORY
    
    if _ENGINE is None:
        _ENGINE = create_engine(
            database_url,
            pool_pre_ping=True,
            pool_recycle=3600,
            echo=False,
            isolation_level="READ COMMITTED"  # ← AGREGAR ESTO
        )
        
        _SESSION_FACTORY = scoped_session(
            sessionmaker(
                bind=_ENGINE,
                expire_on_commit=False,
                autoflush=True,
                autocommit=False
            )
        )

class DBManager(ABC):
    """
    Gestor general para la sesión y operaciones básicas en la base de datos usando SQLAlchemy ORM.

    Implementa gestión de sesiones thread-safe usando scoped_session.
    Cada thread obtiene automáticamente su propia sesión.

    Atributos:
        session (Session): Sesión activa de SQLAlchemy para interactuar con la base de datos.
        logger (Logger): Logger Personalizado para registrar eventos e incidencias.
    """

    def __init__(self, session: Optional[Session] = None):
        """
        Constructor del gestor.

        Args:
            session (Optional[Session]): Sesión SQLAlchemy externa. Si es None,
                                        usa la sesión del thread actual desde el factory.
        """
        global _SESSION_FACTORY

        # Inicializar engine si no existe
        if _SESSION_FACTORY is None:
            initialize_engine()

        if session is not None:
            self.session = session
            self._owns_session = False  # No cerramos sesiones externas
        else:
            # Obtener sesión del thread actual (thread-safe)
            self.session = _SESSION_FACTORY() # type: ignore
            self._owns_session = True

        self.logger = SecOpsLogger(__name__).get_logger()

    def _check_session(self):
        """
        Comprueba que la sesión está inicializada y lista para usarse.

        Raises:
            Exception: Si la sesión es None.
        """
        if self.session is None:
            raise Exception("La sesión de base de datos no está establecida.")

    def close_session(self):
        """
        Cierra la sesión del thread actual si fue creada por este manager.
        """
        if self._owns_session and self.session is not None:
            try:
                self.session.close()
                _SESSION_FACTORY.remove()  # type: ignore
            except Exception as e:
                self.logger.warning(f"Error al cerrar sesión: {e}")

    def _safe_commit(self):
        """
        Realiza un commit seguro con manejo de errores.

        Returns:
            bool: True si el commit fue exitoso, False si falló.
        """
        try:
            self.session.commit()
            return True
        except SQLAlchemyError as err:
            self.logger.error(f"Error durante commit: {err}")
            self._safe_rollback()
            raise

    def _safe_rollback(self):
        """Realiza un rollback seguro solo si la sesión está en un estado que lo permite."""
        try:
            if self.session is not None:
                # Intentar rollback sin importar el estado
                self.session.rollback()
                self.logger.debug("Rollback ejecutado exitosamente")
        except Exception as e:
            self.logger.warning(f"Error durante rollback: {e}")
            # Si el rollback falla, intentar cerrar y recrear la sesión
            try:
                if hasattr(self, "owns_session") and self._owns_session:
                    self.session.close()
                    global _SESSION_FACTORY
                    if _SESSION_FACTORY is not None:
                        self.session = _SESSION_FACTORY()
                        self.logger.info("Sesión recreada después de error en rollback")
            except Exception as recreate_err:
                self.logger.error(f"No se pudo recrear la sesión: {recreate_err}")

    def ensure_session_healthy(self):
        """
        Verifica que la sesión esté en buen estado y la recrea si es necesario.
        """
        try:
            if self.session is None:
                raise Exception("La sesión de base de datos no está establecida.")

            # Verificar si la sesión está en estado de rollback pendiente
            if hasattr(self.session, "_transaction") and self.session._transaction:
                if hasattr(self.session._transaction, "_state"):
                    state = str(self.session._transaction._state)
                    if "DEACTIVE" in state or "rollback" in state.lower():
                        self.logger.warning("Sesión en mal estado, haciendo rollback")
                        self._safe_rollback()
        except Exception as e:
            self.logger.error(f"Error al verificar salud de sesión: {e}")
            self._safe_rollback()

    def _refresh_db(self) -> None:
        """
        Limpia el contenido de las tablas listadas sin modificar su esquema.
        Deshabilita temporalmente las comprobaciones de claves foráneas para evitar errores de integridad
        durante el truncado. Utiliza transacciones para asegurar integridad.

        Raises:
            SQLAlchemyError: Si ocurre un error durante la limpieza, se hace rollback y se propaga la excepción.
        """
        self._check_session()

        tables = [
            "Person",
            "User",
            "Scan",
            "FinishedScan",
            "NmapScan",
            "Port",
            "TargetPort",
            "OpenPort",
            "NiktoScan",
            "NiktoIncident",
            "ScanIncident",
            "OpenVASScan",
        ]

        try:
            self.session.execute(text("SET FOREIGN_KEY_CHECKS=0;"))
            for table in tables:
                self.session.execute(text(f"TRUNCATE TABLE `{table}`;"))
                self.logger.info(f"Tabla '{table}' vaciada correctamente.")
            self.session.execute(text("SET FOREIGN_KEY_CHECKS=1;"))
            self._safe_commit()
            self.logger.info(
                "Todas las tablas han sido limpiadas sin modificar la estructura."
            )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al limpiar tablas: {err}")
            raise

    @staticmethod
    def close_all_sessions():
        """
        Cierra todas las sesiones y limpia el factory.
        Útil para tests o cuando necesites reiniciar completamente las sesiones.
        """
        global _SESSION_FACTORY
        if _SESSION_FACTORY is not None:
            _SESSION_FACTORY.remove()


class UserDBManager(DBManager):
    """
    Gestor específico para operaciones relacionadas con las entidades User y Person usando SQLAlchemy ORM.
    Hereda método y atributos de DBManager para gestión de sesión y logging.
    """

    def validate_credentials(self, username: str, password: str) -> bool:
        self._check_session()
        try:
            user = (
                self.session.query(User)
                .filter(User.username == username, User.password == password)
                .one_or_none()
            )
            is_valid = user is not None
            self.logger.info(
                f"Validación de credenciales para '{username}': {is_valid}"
            )
            return is_valid
        except SQLAlchemyError as err:
            self.logger.error(f"Error al validar credenciales: {err}")
            raise

    def user_exists(self, username: str) -> bool:
        self._check_session()
        try:
            exists = (
                self.session.query(User).filter(User.username == username).count() > 0
            )
            self.logger.info(
                f"Verificación de existencia del User '{username}': {exists}"
            )
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia de User: {err}")
            raise

    def person_exists(self, person_id: int) -> bool:
        self._check_session()
        try:
            exists = (
                self.session.query(Person).filter(Person.id == person_id).count() > 0
            )
            self.logger.info(
                f"Verificación de existencia de la Person con ID '{person_id}': {exists}"
            )
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia de Person: {err}")
            raise

    def create_person(self, person: Person) -> None:
        self._check_session()
        try:
            self.session.add(person)
            self._safe_commit()
            self.logger.info(
                f"Se creó un nuevo Person: {person.first_name} {person.last_name} con ID {person.id}"
            )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al crear Person: {err}")
            raise

    def create_user(self, user: User) -> None:
        self._check_session()
        try:
            if not self.person_exists(user.person_id):  # type: ignore
                self.create_person(user.person)
            self.session.add(user)
            self._safe_commit()
            self.logger.info(
                f"Se creó un nuevo User de sistema: {user.username} con ID {user.id}"
            )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al crear User: {err}")
            raise

    def get_all_people(self) -> List[Person]:
        self._check_session()
        try:
            people = self.session.query(Person).all()
            self.logger.info("Se obtuvieron todos los Person de la base de datos.")
            return people
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener todas las Persons: {err}")
            raise

    def get_person_by_id(self, person_id: int) -> Optional[Person]:
        self._check_session()
        try:
            person = (
                self.session.query(Person).filter(Person.id == person_id).one_or_none()
            )
            self.logger.info(
                f"Se obtuvo el Person con ID {person_id} de la base de datos."
            )
            return person
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener Person por ID: {err}")
            raise

    def get_all_users(self) -> List[User]:
        self._check_session()
        try:
            users = self.session.query(User).all()
            self.logger.info("Se obtuvieron todos los Users de la base de datos.")
            return users
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener todos los Users: {err}")
            raise

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        self._check_session()
        try:
            user = self.session.query(User).filter(User.id == user_id).one_or_none()
            self.logger.info(f"Se obtuvo el User con ID {user_id} de la base de datos.")
            return user
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener User por ID: {err}")
            raise

    def get_user_by_username(self, username: str) -> Optional[User]:
        self._check_session()
        try:
            user = (
                self.session.query(User).filter(User.username == username).one_or_none()
            )
            self.logger.info(
                f"Se obtuvo el User con username '{username}' de la base de datos."
            )
            return user
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener User por username: {err}")
            raise

    def get_person_by_email(self, email: str) -> Optional[Person]:
        self._check_session()
        try:
            person = (
                self.session.query(Person).filter(Person.email == email).one_or_none()
            )
            self.logger.info(
                f"Se obtuvo el Person con email '{email}' de la base de datos."
            )
            return person
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener Person por email: {err}")
            raise

    def update_person(self, person: Person) -> None:
        self._check_session()
        try:
            existing_person = (
                self.session.query(Person).filter(Person.id == person.id).one_or_none()
            )
            if existing_person:
                existing_person.first_name = person.first_name
                existing_person.last_name = person.last_name
                existing_person.email = person.email
                self._safe_commit()
                self.logger.info(
                    f"Se actualizó la información de la Person con ID {person.id}."
                )
            else:
                self.logger.warning(
                    f"No se encontró Person con ID {person.id} para actualizar."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al actualizar Person: {err}")
            raise

    def update_user(self, user: User) -> None:
        self._check_session()
        try:
            existing_user = (
                self.session.query(User).filter(User.id == user.id).one_or_none()
            )
            if existing_user:
                existing_user.username = user.username
                existing_user.password_hash = user.password_hash
                self._safe_commit()
                self.logger.info(
                    f"Se actualizó la información del User con ID {user.id}."
                )
            else:
                self.logger.warning(
                    f"No se encontró User con ID {user.id} para actualizar."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al actualizar User: {err}")
            raise

    def delete_user(self, user: User) -> None:
        self._check_session()
        try:
            existing_user = (
                self.session.query(User).filter(User.id == user.id).one_or_none()
            )
            if existing_user:
                self.session.delete(existing_user)
                self._safe_commit()
                self.logger.info(
                    f"Se eliminó el User con ID {user.id} de la base de datos."
                )
            else:
                self.logger.warning(
                    f"No se encontró User con ID {user.id} para eliminar."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al eliminar User: {err}")
            raise

    def delete_person(self, person: Person) -> None:
        self._check_session()
        try:
            existing_person = (
                self.session.query(Person).filter(Person.id == person.id).one_or_none()
            )
            if existing_person:
                self.session.delete(existing_person)
                self._safe_commit()
                self.logger.info(
                    f"Se eliminó la Person con ID {person.id} de la base de datos."
                )
            else:
                self.logger.warning(
                    f"No se encontró Person con ID {person.id} para eliminar."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al eliminar Person: {err}")
            raise


class ScanDBManager(DBManager):
    """
    Clase para gestionar operaciones específicas de escaneos en la base de datos.
    """

    def scan_exists(self, scan_id: int) -> bool:
        self._check_session()
        try:
            exists = self.session.query(Scan).filter(Scan.id == scan_id).count() > 0
            self.logger.info(
                f"Verificación de existencia del escaneo con ID '{scan_id}': {exists}"
            )
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia del escaneo: {err}")
            raise

    def create_scan(self, scan: Scan) -> None:
        self._check_session()
        try:
            self.session.add(scan)
            self._safe_commit()
            self.logger.info(f"Se creó un nuevo escaneo con ID {scan.id}")
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al crear escaneo: {err}")
            raise

    def get_scan_by_id(self, scan_id: int) -> Optional[Scan]:
        self._check_session()
        try:
            scan = self.session.query(Scan).filter(Scan.id == scan_id).one_or_none()
            self.logger.info(
                f"Se obtuvo el escaneo con ID {scan_id} de la base de datos."
            )
            return scan
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener escaneo por ID: {err}")
            raise

    def get_next_scan_id(self) -> int:
        self._check_session()
        try:
            result = self.session.execute(
                text(
                    "SELECT AUTO_INCREMENT FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'Scan';"
                )
            )
            next_id = result.scalar_one()
            self.logger.info(f"Próximo ID disponible para Scan: {next_id}")
            return next_id
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener próximo ID para Scan: {err}")
            raise

    def update_scan(self, scan: Scan) -> None:
        self._check_session()
        try:
            existing_scan = (
                self.session.query(Scan).filter(Scan.id == scan.id).one_or_none()
            )
            if existing_scan:
                existing_scan.target = scan.target
                existing_scan.started_at = scan.started_at
                self._safe_commit()
                self.logger.info(
                    f"Se actualizó la información del escaneo con ID {scan.id}."
                )
            else:
                self.logger.warning(
                    f"No se encontró escaneo con ID {scan.id} para actualizar."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al actualizar escaneo: {err}")
            raise

    def delete_scan(self, scan: Scan) -> None:
        self._check_session()
        try:
            existing_scan = (
                self.session.query(Scan).filter(Scan.id == scan.id).one_or_none()
            )
            if existing_scan:
                self.session.delete(existing_scan)
                self._safe_commit()
                self.logger.info(
                    f"Se eliminó el escaneo con ID {scan.id} de la base de datos."
                )
            else:
                self.logger.warning(
                    f"No se encontró escaneo con ID {scan.id} para eliminar."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al eliminar escaneo: {err}")
            raise

    def scan_is_finished(self, scan_id: int) -> bool:
        existe_escaneo = self.scan_exists(scan_id)
        if not existe_escaneo:
            self.logger.error(f"El escaneo con el siguiente id: {scan_id} no existe")
            return False

        try:
            # SOLUCIÓN: Cerrar cualquier transacción pendiente y empezar una nueva
            self.session.commit()  # Cierra la transacción actual
            
            self.logger.info(f"[DEBUG] Verificando FinishedScan para scan_id={scan_id}")
            self.logger.info(f"[DEBUG] Session ID: {id(self.session)}")
            
            # Ahora la consulta verá los commits de otros threads
            from sqlalchemy import text
            result = self.session.execute(
                text("SELECT COUNT(*) FROM FinishedScan WHERE id = :scan_id"),
                {"scan_id": scan_id}
            )
            count_direct = result.scalar()
            self.logger.info(f"[DEBUG] SQL directo COUNT: {count_direct}")
            
            exists = count_direct > 0 #type: ignore
            self.logger.info(f"[DEBUG] Result: {exists}")
            
            return exists
        
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia del escaneo: {err}")
            self._safe_rollback()
            raise

    def set_scan_as_finished(self, scan: Scan) -> bool:
        """
        Marca un escaneo como finalizado creando un registro en FinishedScan.
        """
        try:            
            # Crear el registro FinishedScan
            finished_scan = FinishedScan(
                id=scan.id
            )
            finished_scan.finished_at = datetime.now() #type: ignore
            
            # Guardar en la base de datos
            self.session.add(finished_scan)
            self.session.flush()  # ← AGREGAR ESTO
            self._safe_commit()
            
            # VERIFICAR que se guardó
            self.logger.info(f"[DEBUG] Commit realizado para scan {scan.id}")
            
            # Hacer una verificación directa
            from sqlalchemy import text
            result = self.session.execute(
                text("SELECT COUNT(*) FROM FinishedScan WHERE id = :scan_id"),
                {"scan_id": scan.id}
            )
            count = result.scalar()
            self.logger.info(f"[DEBUG] Verificación post-commit: COUNT={count}")
            
            return True
            
        except Exception as e:
            self.logger.error(
                f"Error al marcar escaneo {scan.id} como finalizado: {e}",
                exc_info=True
            )
            try:
                self._safe_rollback()
            except:
                pass
            return False


class NmapDBManager(ScanDBManager):
    """
    Gestor específico para operaciones relacionadas con escaneos Nmap y puertos.
    """

    # MÉTODOS PARA PORT
    def port_exists(self, port_id: int) -> bool:
        self._check_session()
        try:
            exists = self.session.query(Port).filter(Port.id == port_id).count() > 0
            self.logger.info(
                f"Verificación de existencia del puerto con ID '{port_id}': {exists}"
            )
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia del puerto: {err}")
            raise

    def port_exists_by_protocol(self, protocol: str) -> bool:
        self._check_session()
        try:
            exists = (
                self.session.query(Port).filter(Port.protocol == protocol).count() > 0
            )
            self.logger.info(
                f"Verificación de existencia del puerto '{protocol}': {exists}"
            )
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia del puerto: {err}")
            raise

    def create_port(self, port: Port) -> None:
        self._check_session()
        try:
            self.session.add(port)
            self._safe_commit()
            self.logger.info(
                f"Se creó un nuevo puerto: {port.protocol} con ID {port.id}"
            )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al crear puerto: {err}")
            raise

    def get_or_create_port(self, protocol: str) -> Port:
        self._check_session()
        try:
            port = self.get_port_by_protocol(protocol)
            if port:
                self.logger.info(f"Puerto '{protocol}' ya existe, reutilizando.")
                return port
            new_port = Port(protocol=protocol)
            self.create_port(new_port)
            self.logger.info(f"Puerto '{protocol}' creado con ID {new_port.id}")
            return new_port
        except SQLAlchemyError as err:
            self.logger.error(f"Error en get_or_create_port: {err}")
            raise

    def get_port_by_id(self, port_id: int) -> Optional[Port]:
        self._check_session()
        try:
            port = self.session.query(Port).filter(Port.id == port_id).one_or_none()
            self.logger.info(
                f"Se obtuvo el puerto con ID {port_id} de la base de datos."
            )
            return port
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener puerto por ID: {err}")
            raise

    def get_port_by_protocol(self, protocol: str) -> Optional[Port]:
        self._check_session()
        try:
            port = (
                self.session.query(Port).filter(Port.protocol == protocol).one_or_none()
            )
            if port:
                self.logger.info(f"Se obtuvo el puerto '{protocol}' con ID {port.id}.")
            else:
                self.logger.info(f"No se encontró puerto con protocolo '{protocol}'.")
            return port
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener puerto por protocolo: {err}")
            raise

    def get_all_ports(self) -> List[Port]:
        self._check_session()
        try:
            ports = self.session.query(Port).all()
            self.logger.info(f"Se obtuvieron {len(ports)} puertos de la base de datos.")
            return ports
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener todos los puertos: {err}")
            raise

    def update_port(self, port: Port) -> None:
        self._check_session()
        try:
            existing_port = (
                self.session.query(Port).filter(Port.id == port.id).one_or_none()
            )
            if existing_port:
                existing_port.protocol = port.protocol
                self._safe_commit()
                self.logger.info(
                    f"Se actualizó la información del puerto con ID {port.id}."
                )
            else:
                self.logger.warning(
                    f"No se encontró puerto con ID {port.id} para actualizar."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al actualizar puerto: {err}")
            raise

    def delete_port(self, port: Port) -> None:
        self._check_session()
        try:
            existing_port = (
                self.session.query(Port).filter(Port.id == port.id).one_or_none()
            )
            if existing_port:
                self.session.delete(existing_port)
                self._safe_commit()
                self.logger.info(
                    f"Se eliminó el puerto '{port.protocol}' con ID {port.id}."
                )
            else:
                self.logger.warning(
                    f"No se encontró puerto con ID {port.id} para eliminar."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al eliminar puerto: {err}")
            raise

    # MÉTODOS PARA NMAPSCAN
    def nmap_scan_exists(self, scan_id: int) -> bool:
        self._check_session()
        try:
            exists = (
                self.session.query(NmapScan).filter(NmapScan.id == scan_id).count() > 0
            )
            self.logger.info(
                f"Verificación de existencia del escaneo Nmap con ID '{scan_id}': {exists}"
            )
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia del escaneo Nmap: {err}")
            raise

    def create_nmap_scan(self, scan: NmapScan) -> None:
        self._check_session()
        try:
            self.session.add(scan)
            self._safe_commit()
            self.logger.info(
                f"Se creó un nuevo escaneo Nmap con ID {scan.id} para target '{scan.target}'"
            )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al crear escaneo Nmap: {err}")
            raise

    def get_nmap_scan_by_id(self, scan_id: int) -> Optional[NmapScan]:
        self._check_session()
        try:
            scan = (
                self.session.query(NmapScan)
                .filter(NmapScan.id == scan_id)
                .one_or_none()
            )
            self.logger.info(f"Se obtuvo el escaneo Nmap con ID {scan_id}.")
            return scan
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener escaneo Nmap por ID: {err}")
            raise

    def get_all_nmap_scans(self) -> List[NmapScan]:
        self._check_session()
        try:
            scans = self.session.query(NmapScan).all()
            self.logger.info(
                f"Se obtuvieron {len(scans)} escaneos Nmap de la base de datos."
            )
            return scans
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener todos los escaneos Nmap: {err}")
            raise

    def get_nmap_scans_by_user(self, user_id: int) -> List[NmapScan]:
        self._check_session()
        try:
            scans = (
                self.session.query(NmapScan).filter(NmapScan.user_id == user_id).all()
            )
            self.logger.info(
                f"Se obtuvieron {len(scans)} escaneos Nmap del usuario con ID {user_id}."
            )
            return scans
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener escaneos Nmap por usuario: {err}")
            raise

    def update_nmap_scan(self, scan: NmapScan) -> None:
        self._check_session()
        try:
            existing_scan = (
                self.session.query(NmapScan)
                .filter(NmapScan.id == scan.id)
                .one_or_none()
            )
            if existing_scan:
                existing_scan.target = scan.target
                existing_scan.started_at = scan.started_at
                self._safe_commit()
                self.logger.info(f"Se actualizó el escaneo Nmap con ID {scan.id}.")
            else:
                self.logger.warning(
                    f"No se encontró escaneo Nmap con ID {scan.id} para actualizar."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al actualizar escaneo Nmap: {err}")
            raise

    def delete_nmap_scan(self, scan: NmapScan) -> None:
        self._check_session()
        try:
            existing_scan = (
                self.session.query(NmapScan)
                .filter(NmapScan.id == scan.id)
                .one_or_none()
            )
            if existing_scan:
                self.session.delete(existing_scan)
                self._safe_commit()
                self.logger.info(f"Se eliminó el escaneo Nmap con ID {scan.id}.")
            else:
                self.logger.warning(
                    f"No se encontró escaneo Nmap con ID {scan.id} para eliminar."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al eliminar escaneo Nmap: {err}")
            raise

    # MÉTODOS PARA GESTIONAR RELACIONES
    def add_target_port(self, scan: NmapScan, port: Port) -> None:
        self._check_session()
        try:
            if port not in scan.target_ports:
                scan.target_ports.append(port)
                self._safe_commit()
                self.logger.info(
                    f"Puerto '{port.protocol}' añadido como objetivo al escaneo {scan.id}."
                )
            else:
                self.logger.info(
                    f"Puerto '{port.protocol}' ya está en los objetivos del escaneo {scan.id}."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al añadir puerto objetivo: {err}")
            raise

    def add_target_ports(self, scan: NmapScan, ports: List[Port]) -> None:
        self._check_session()
        try:
            added = 0
            for port in ports:
                if port not in scan.target_ports:
                    scan.target_ports.append(port)
                    added += 1
            self._safe_commit()
            self.logger.info(
                f"Se añadieron {added} puertos objetivo al escaneo {scan.id}."
            )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al añadir puertos objetivo: {err}")
            raise

    def remove_target_port(self, scan: NmapScan, port: Port) -> None:
        self._check_session()
        try:
            if port in scan.target_ports:
                scan.target_ports.remove(port)
                self._safe_commit()
                self.logger.info(
                    f"Puerto '{port.protocol}' eliminado de los objetivos del escaneo {scan.id}."
                )
            else:
                self.logger.warning(
                    f"Puerto '{port.protocol}' no está en los objetivos del escaneo {scan.id}."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al eliminar puerto objetivo: {err}")
            raise

    def get_target_ports(self, scan: NmapScan) -> List[Port]:
        self._check_session()
        try:
            ports = scan.target_ports
            self.logger.info(
                f"Se obtuvieron {len(ports)} puertos objetivo del escaneo {scan.id}."
            )
            return ports
        except Exception as err:
            self.logger.error(f"Error al obtener puertos objetivo: {err}")
            raise

    def add_open_port(self, scan: NmapScan, port: Port, reason: str) -> None:
        self._check_session()
        try:
            # Verificar si ya existe
            existing = (
                self.session.query(OpenPort)
                .filter(OpenPort.port_id == port.id, OpenPort.nmap_scan_id == scan.id)
                .first()
            )

            if existing:
                self.logger.info(
                    f"Puerto '{port.protocol}' ya está marcado como abierto en el escaneo {scan.id}."
                )
                return

            open_port = OpenPort(port_id=port.id, nmap_scan_id=scan.id, reason=reason)
            self.session.add(open_port)
            self._safe_commit()
            self.logger.info(
                f"Puerto '{port.protocol}' marcado como abierto en escaneo {scan.id} (razón: {reason})."
            )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al añadir puerto abierto: {err}")
            raise

    def remove_open_port(self, scan: NmapScan, port: Port) -> None:
        self._check_session()
        try:
            open_port = (
                self.session.query(OpenPort)
                .filter(OpenPort.port_id == port.id, OpenPort.nmap_scan_id == scan.id)
                .first()
            )

            if open_port:
                self.session.delete(open_port)
                self._safe_commit()
                self.logger.info(
                    f"Puerto '{port.protocol}' eliminado de puertos abiertos del escaneo {scan.id}."
                )
            else:
                self.logger.warning(
                    f"Puerto '{port.protocol}' no está en los puertos abiertos del escaneo {scan.id}."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al eliminar puerto abierto: {err}")
            raise

    def get_open_ports(self, scan: NmapScan) -> List[OpenPort]:
        self._check_session()
        try:
            open_ports = scan.open_ports_relation
            self.logger.info(
                f"Se obtuvieron {len(open_ports)} puertos abiertos del escaneo {scan.id}."
            )
            return open_ports
        except Exception as err:
            self.logger.error(f"Error al obtener puertos abiertos: {err}")
            raise
        


class NiktoDBManager(ScanDBManager):
    """
    Gestor específico para operaciones relacionadas con escaneos Nikto e incidentes.
    """

    def nikto_incident_exists(self, incident_id: int) -> bool:
        self._check_session()
        try:
            exists = (
                self.session.query(NiktoIncident)
                .filter(NiktoIncident.id == incident_id)
                .count()
                > 0
            )
            self.logger.info(
                f"Verificación de existencia del incidente Nikto con ID '{incident_id}': {exists}"
            )
            return exists
        except SQLAlchemyError as err:
            self.logger.error(
                f"Error al verificar existencia del incidente Nikto: {err}"
            )
            raise

    def nikto_incident_exists_with_desc(self, incident_desc: str) -> bool:
        self._check_session()
        try:
            exists = (
                self.session.query(NiktoIncident)
                .filter(NiktoIncident.description == incident_desc)
                .count()
                > 0
            )
            self.logger.info(
                f"Verificación de existencia del incidente Nikto con descripción '{incident_desc}': {exists}"
            )
            return exists
        except SQLAlchemyError as err:
            self.logger.error(
                f"Error al verificar existencia del incidente Nikto: {err}"
            )
            raise

    def create_nikto_incident(self, incident: NiktoIncident) -> None:
        self._check_session()
        try:
            self.session.add(incident)
            self._safe_commit()
            self.logger.info(f"Se creó un nuevo incidente Nikto con ID {incident.id}")
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al crear incidente Nikto: {err}")
            raise

    def get_nikto_incident_by_id(self, incident_id: int) -> Optional[NiktoIncident]:
        self._check_session()
        try:
            incident = (
                self.session.query(NiktoIncident)
                .filter(NiktoIncident.id == incident_id)
                .one_or_none()
            )
            self.logger.info(f"Se obtuvo el incidente Nikto con ID {incident_id}.")
            return incident
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener incidente Nikto por ID: {err}")
            raise

    def get_nikto_incident_by_description(
        self, incident_description: str
    ) -> Optional[NiktoIncident]:
        self._check_session()
        try:
            incident = (
                self.session.query(NiktoIncident)
                .filter(NiktoIncident.description == incident_description)
                .one_or_none()
            )
            self.logger.info(
                f"Se obtuvo el incidente Nikto con descripción '{incident_description}'."
            )
            return incident
        except SQLAlchemyError as err:
            self.logger.error(
                f"Error al obtener incidente Nikto por descripción: {err}"
            )
            raise

    def get_all_nikto_incidents(self) -> List[NiktoIncident]:
        self._check_session()
        try:
            incidents = self.session.query(NiktoIncident).all()
            self.logger.info(
                f"Se obtuvieron {len(incidents)} incidentes Nikto de la base de datos."
            )
            return incidents
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener todos los incidentes Nikto: {err}")
            raise

    def get_or_create_nikto_incident(self, incident: NiktoIncident) -> NiktoIncident:
        self._check_session()
        try:
            new_incident = self.get_nikto_incident_by_description(incident.description)  # type: ignore
            if new_incident:
                self.logger.info(
                    f"Incidente '{incident.description}' ya existe, reutilizando."
                )
                return new_incident
            self.create_nikto_incident(incident)
            self.logger.info(
                f"Incidente '{incident.description}' creado con ID {incident.id}"
            )
            return incident
        except SQLAlchemyError as err:
            self.logger.error(f"Error en get_or_create_nikto_incident: {err}")
            raise

    def update_nikto_incident(self, incident: NiktoIncident) -> None:
        self._check_session()
        try:
            existing_incident = (
                self.session.query(NiktoIncident)
                .filter(NiktoIncident.id == incident.id)
                .one_or_none()
            )
            if existing_incident:
                self._safe_commit()
                self.logger.info(
                    f"Se actualizó el incidente Nikto con ID {incident.id}."
                )
            else:
                self.logger.warning(
                    f"No se encontró incidente Nikto con ID {incident.id} para actualizar."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al actualizar incidente Nikto: {err}")
            raise

    def delete_nikto_incident(self, incident: NiktoIncident) -> None:
        self._check_session()
        try:
            existing_incident = (
                self.session.query(NiktoIncident)
                .filter(NiktoIncident.id == incident.id)
                .one_or_none()
            )
            if existing_incident:
                self.session.delete(existing_incident)
                self._safe_commit()
                self.logger.info(f"Se eliminó el incidente Nikto con ID {incident.id}.")
            else:
                self.logger.warning(
                    f"No se encontró incidente Nikto con ID {incident.id} para eliminar."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al eliminar incidente Nikto: {err}")
            raise

    # MÉTODOS PARA NIKTOSCAN
    def nikto_scan_exists(self, scan_id: int) -> bool:
        self._check_session()
        try:
            exists = (
                self.session.query(NiktoScan).filter(NiktoScan.id == scan_id).count()
                > 0
            )
            self.logger.info(
                f"Verificación de existencia del escaneo Nikto con ID '{scan_id}': {exists}"
            )
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia del escaneo Nikto: {err}")
            raise

    def create_nikto_scan(self, scan: NiktoScan) -> None:
        self._check_session()
        try:
            self.session.add(scan)
            self._safe_commit()
            self.logger.info(
                f"Se creó un nuevo escaneo Nikto con ID {scan.id} para target '{scan.target}'"
            )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al crear escaneo Nikto: {err}")
            raise

    def get_nikto_scan_by_id(self, scan_id: int) -> Optional[NiktoScan]:
        self._check_session()
        try:
            scan = (
                self.session.query(NiktoScan)
                .filter(NiktoScan.id == scan_id)
                .one_or_none()
            )
            self.logger.info(f"Se obtuvo el escaneo Nikto con ID {scan_id}.")
            return scan
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener escaneo Nikto por ID: {err}")
            raise

    def get_all_nikto_scans(self) -> List[NiktoScan]:
        self._check_session()
        try:
            scans = self.session.query(NiktoScan).all()
            self.logger.info(
                f"Se obtuvieron {len(scans)} escaneos Nikto de la base de datos."
            )
            return scans
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener todos los escaneos Nikto: {err}")
            raise

    def get_nikto_scans_by_user(self, user_id: int) -> List[NiktoScan]:
        self._check_session()
        try:
            scans = (
                self.session.query(NiktoScan).filter(NiktoScan.user_id == user_id).all()
            )
            self.logger.info(
                f"Se obtuvieron {len(scans)} escaneos Nikto del usuario con ID {user_id}."
            )
            return scans
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener escaneos Nikto por usuario: {err}")
            raise

    def update_nikto_scan(self, scan: NiktoScan) -> None:
        self._check_session()
        try:
            existing_scan = (
                self.session.query(NiktoScan)
                .filter(NiktoScan.id == scan.id)
                .one_or_none()
            )
            if existing_scan:
                existing_scan.target = scan.target
                existing_scan.started_at = scan.started_at
                self._safe_commit()
                self.logger.info(f"Se actualizó el escaneo Nikto con ID {scan.id}.")
            else:
                self.logger.warning(
                    f"No se encontró escaneo Nikto con ID {scan.id} para actualizar."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al actualizar escaneo Nikto: {err}")
            raise

    def delete_nikto_scan(self, scan: NiktoScan) -> None:
        self._check_session()
        try:
            existing_scan = (
                self.session.query(NiktoScan)
                .filter(NiktoScan.id == scan.id)
                .one_or_none()
            )
            if existing_scan:
                self.session.delete(existing_scan)
                self._safe_commit()
                self.logger.info(f"Se eliminó el escaneo Nikto con ID {scan.id}.")
            else:
                self.logger.warning(
                    f"No se encontró escaneo Nikto con ID {scan.id} para eliminar."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al eliminar escaneo Nikto: {err}")
            raise

    # MÉTODOS PARA GESTIONAR RELACIONES
    def add_incident(self, scan: NiktoScan, incident: NiktoIncident) -> None:
        self._check_session()
        try:
            if incident not in scan.incidents:
                scan.incidents.append(incident)
                self._safe_commit()
                self.logger.info(
                    f"Incidente con ID {incident.id} añadido al escaneo Nikto {scan.id}."
                )
            else:
                self.logger.info(
                    f"Incidente con ID {incident.id} ya está asociado al escaneo Nikto {scan.id}."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al añadir incidente: {err}")
            raise

    def add_incidents(self, scan: NiktoScan, incidents: List[NiktoIncident]) -> None:
        self._check_session()
        try:
            added = 0
            for incident in incidents:
                if incident not in scan.incidents:
                    scan.incidents.append(incident)
                    added += 1
            self._safe_commit()
            self.logger.info(
                f"Se añadieron {added} incidentes al escaneo Nikto {scan.id}."
            )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al añadir incidentes: {err}")
            raise

    def remove_incident(self, scan: NiktoScan, incident: NiktoIncident) -> None:
        self._check_session()
        try:
            if incident in scan.incidents:
                scan.incidents.remove(incident)
                self._safe_commit()
                self.logger.info(
                    f"Incidente con ID {incident.id} eliminado del escaneo Nikto {scan.id}."
                )
            else:
                self.logger.warning(
                    f"Incidente con ID {incident.id} no está asociado al escaneo Nikto {scan.id}."
                )
        except SQLAlchemyError as err:
            self._safe_rollback()
            self.logger.error(f"Error al eliminar incidente: {err}")
            raise

    def get_scan_incidents(self, scan: NiktoScan) -> List[NiktoIncident]:
        self._check_session()
        try:
            incidents = scan.incidents
            self.logger.info(
                f"Se obtuvieron {len(incidents)} incidentes del escaneo Nikto {scan.id}."
            )
            return incidents
        except Exception as err:
            self.logger.error(f"Error al obtener incidentes del escaneo: {err}")
            raise
