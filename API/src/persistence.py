from sqlalchemy import text, create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError
from typing import List, Optional
from abc import ABC
import urllib.parse

from src.misc.logging import SecOpsLogger
from src.model import Person, User, Scan, Port, OpenPort, NmapScan, NiktoIncident, NiktoScan
from src.misc.configread import ConfigReader


# Obtener credenciales para la conexión a la base de datos y construir la URL de conexión MySQL
(USERNAME, PASSWORD, HOST, DBNAME) = ConfigReader().get_db_crendetials()
DEFAULT_DATABASE_URL = f"mysql+pymysql://{USERNAME}:{urllib.parse.quote(PASSWORD)}@{HOST}/{DBNAME}"


SHARED_SESSION: Optional[Session] = None


class DBManager(ABC):
    """
    Gestor general para la sesión y operaciones básicas en la base de datos usando SQLAlchemy ORM.
    
    Implementa un patrón Singleton para la sesión: todas las instancias comparten la misma sesión.

    Atributos:
        session (Session): Sesión activa de SQLAlchemy para interactuar con la base de datos.
        logger (Logger): Logger Personalizado para registrar eventos e incidencias.
    
    Métodos:
        __init__(session: Optional[Session] = None):
            Inicializa la sesión de base de datos. Si no se pasa una sesión, crea una a partir
            de la URL por defecto o reutiliza la sesión compartida existente.

        _check_session():
            Verifica que la sesión esté establecida antes de realizar operaciones.

        _refresh_db():
            Vacía el contenido de tablas específicas sin borrar su estructura, útil para tests o reinicio de datos.
    """

    def __init__(self, session: Optional[Session] = None):
        """
        Constructor del gestor.

        Args:
            session (Optional[Session]): Sesión SQLAlchemy externa. Si es None, 
                                         usa o crea la sesión compartida singleton.
        """
        global SHARED_SESSION
        
        if session is not None:
            self.session = session
        elif SHARED_SESSION is not None:
            self.session = SHARED_SESSION
        else:
            # Crear nueva sesión y establecerla como compartida
            engine = create_engine(DEFAULT_DATABASE_URL)
            SessionLocal = sessionmaker(bind=engine)
            self.session = SessionLocal()
            SHARED_SESSION = self.session

        self.logger = SecOpsLogger(__name__).get_logger()

    def _check_session(self):
        """
        Comprueba que la sesión está inicializada y lista para usarse.

        Raises:
            Exception: Si la sesión es None.
        """
        if self.session is None:
            raise Exception("La sesión de base de datos no está establecida.")

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
            "OpenVASScan"
        ]

        try:
            self.session.execute(text("SET FOREIGN_KEY_CHECKS=0;"))
            for table in tables:
                self.session.execute(text(f"TRUNCATE TABLE `{table}`;"))
                self.logger.info(f"Tabla '{table}' vaciada correctamente.")
            self.session.execute(text("SET FOREIGN_KEY_CHECKS=1;"))
            self.session.commit()
            self.logger.info("Todas las tablas han sido limpiadas sin modificar la estructura.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al limpiar tablas: {err}")
            raise

    @staticmethod
    def close_shared_session():
        """
        Cierra la sesión compartida si existe y la resetea.
        Útil para tests o cuando necesites reiniciar completamente la sesión.
        """
        global SHARED_SESSION
        if SHARED_SESSION is not None:
            SHARED_SESSION.close()
            SHARED_SESSION = None


class UserDBManager(DBManager):
    """
    Gestor específico para operaciones relacionadas con las entidades User y Person usando SQLAlchemy ORM.

    Hereda método y atributos de DBManager para gestión de sesión y logging.

    Métodos CRUD para User y Person:
        - user_exists(username: str) -> bool
        - person_exists(person_id: int) -> bool
        - create_person(person: Person) -> None
        - create_user(user: User) -> None
        - get_all_people() -> List[Person]
        - get_person_by_id(person_id: int) -> Optional[Person]
        - get_all_users() -> List[User]
        - get_user_by_id(user_id: int) -> Optional[User]
        - update_person(person: Person) -> None
        - update_user(user: User) -> None
        - delete_user(user: User) -> None
        - delete_person(person: Person) -> None
    """

    def user_exists(self, username: str) -> bool:
        """
        Verifica si existe un User con el username indicado.

        Args:
            username (str): Nombre de usuario a buscar.

        Returns:
            bool: True si existe, False en caso contrario.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            exists = self.session.query(User).filter(User.username == username).count() > 0
            self.logger.info(f"Verificación de existencia del User '{username}': {exists}")
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia de User: {err}")
            raise

    def person_exists(self, person_id: int) -> bool:
        """
        Verifica si existe una Person con el ID indicado.

        Args:
            person_id (int): ID de la Persona a buscar.

        Returns:
            bool: True si existe, False en caso contrario.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            exists = self.session.query(Person).filter(Person.id == person_id).count() > 0
            self.logger.info(f"Verificación de existencia de la Person con ID '{person_id}': {exists}")
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia de Person: {err}")
            raise

    def create_person(self, person: Person) -> None:
        """
        Añade una nueva Persona a la base de datos.

        Args:
            person (Person): Objeto Person a crear.

        Raises:
            SQLAlchemyError: En caso de error durante la inserción.
        """
        self._check_session()
        try:
            self.session.add(person)
            self.session.commit()
            self.logger.info(f"Se creó un nuevo Person: {person.first_name} {person.last_name} con ID {person.id}")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al crear Person: {err}")
            raise

    def create_user(self, user: User) -> None:
        """
        Añade un nuevo usuario al sistema. Crea la Person relacionada si no existe.

        Args:
            user (User): Objeto User a crear, debe tener el atributo person asociado.

        Raises:
            SQLAlchemyError: En caso de error durante la inserción.
        """
        self._check_session()
        try:
            if not self.person_exists(user.person_id): # type: ignore
                self.create_person(user.person)
            self.session.add(user)
            self.session.commit()
            self.logger.info(f"Se creó un nuevo User de sistema: {user.username} con ID {user.id}")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al crear User: {err}")
            raise

    def get_all_people(self) -> List[Person]:
        """
        Obtiene todos los registros de Person existentes.

        Returns:
            List[Person]: Lista de todos los objetos Person.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            people = self.session.query(Person).all()
            self.logger.info("Se obtuvieron todos los Person de la base de datos.")
            return people
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener todas las Persons: {err}")
            raise

    def get_person_by_id(self, person_id: int) -> Optional[Person]:
        """
        Obtiene un objeto Person dado su ID.

        Args:
            person_id (int): ID del objeto Person a obtener.

        Returns:
            Optional[Person]: Objeto Person si existe, None si no.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            person = self.session.query(Person).filter(Person.id == person_id).one_or_none()
            self.logger.info(f"Se obtuvo el Person con ID {person_id} de la base de datos.")
            return person
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener Person por ID: {err}")
            raise

    def get_all_users(self) -> List[User]:
        """
        Obtiene todos los objetos User existentes.

        Returns:
            List[User]: Lista de todos los usuarios.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            users = self.session.query(User).all()
            self.logger.info("Se obtuvieron todos los Users de la base de datos.")
            return users
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener todos los Users: {err}")
            raise

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        Obtiene un objeto User dado su ID.

        Args:
            user_id (int): ID del usuario a obtener.

        Returns:
            Optional[User]: Objeto User si existe, None si no.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            user = self.session.query(User).filter(User.id == user_id).one_or_none()
            self.logger.info(f"Se obtuvo el User con ID {user_id} de la base de datos.")
            return user
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener User por ID: {err}")
            raise

    def update_person(self, person: Person) -> None:
        """
        Actualiza la información de una Person existente.

        Args:
            person (Person): Objeto Person con los datos actualizados.

        Raises:
            SQLAlchemyError: En caso de error durante la actualización.
        """
        self._check_session()
        try:
            # CORREGIDO: person.id en lugar de Person.id
            existing_person = self.session.query(Person).filter(Person.id == person.id).one_or_none()
            if existing_person:
                existing_person.first_name = person.first_name
                existing_person.last_name = person.last_name
                existing_person.email = person.email
                self.session.commit()
                self.logger.info(f"Se actualizó la información de la Person con ID {person.id}.")
            else:
                self.logger.warning(f"No se encontró Person con ID {person.id} para actualizar.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al actualizar Person: {err}")
            raise

    def update_user(self, user: User) -> None:
        """
        Actualiza la información de un User existente.

        Args:
            user (User): Objeto User con los datos actualizados.

        Raises:
            SQLAlchemyError: En caso de error durante la actualización.
        """
        self._check_session()
        try:
            existing_user = self.session.query(User).filter(User.id == user.id).one_or_none()
            if existing_user:
                existing_user.username = user.username
                existing_user.password = user.password
                # No actualices el ID, es la clave primaria
                self.session.commit()
                self.logger.info(f"Se actualizó la información del User con ID {user.id}.")
            else:
                self.logger.warning(f"No se encontró User con ID {user.id} para actualizar.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al actualizar User: {err}")
            raise

    def delete_user(self, user: User) -> None:
        """
        Elimina un User existente.

        Args:
            user (User): Objeto User a eliminar.

        Raises:
            SQLAlchemyError: En caso de error durante la eliminación.
        """
        self._check_session()
        try:
            existing_user = self.session.query(User).filter(User.id == user.id).one_or_none()
            if existing_user:
                self.session.delete(existing_user)
                self.session.commit()
                self.logger.info(f"Se eliminó el User con ID {user.id} de la base de datos.")
            else:
                self.logger.warning(f"No se encontró User con ID {user.id} para eliminar.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al eliminar User: {err}")
            raise

    def delete_person(self, person: Person) -> None:
        """
        Elimina una Person existente.

        Args:
            person (Person): Objeto Person a eliminar.

        Raises:
            SQLAlchemyError: En caso de error durante la eliminación.
        """
        self._check_session()
        try:
            # CORREGIDO: person.id en lugar de Person.id
            existing_person = self.session.query(Person).filter(Person.id == person.id).one_or_none()
            if existing_person:
                self.session.delete(existing_person)
                self.session.commit()
                self.logger.info(f"Se eliminó la Person con ID {person.id} de la base de datos.")
            else:
                self.logger.warning(f"No se encontró Person con ID {person.id} para eliminar.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al eliminar Person: {err}")
            raise


class ScanDBManager(DBManager):
    """
    Clase para gestionar operaciones específicas de escaneos en la base de datos.
    """

    #==============================================================
    # EXIST
    #==============================================================
    def scan_exists(self, scan_id: int) -> bool:
        """
        Verifica si existe un escaneo con el ID indicado.

        Args:
            scan_id (int): ID del escaneo a buscar.

        Returns:
            bool: True si existe, False en caso contrario.
        """
        self._check_session()
        try:
            exists = self.session.query(Scan).filter(Scan.id == scan_id).count() > 0
            self.logger.info(f"Verificación de existencia del escaneo con ID '{scan_id}': {exists}")
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia del escaneo: {err}")
            raise

    #==============================================================
    # CREATE
    #==============================================================    
    def create_scan(self, scan: Scan) -> None:
        """
        Añade un nuevo escaneo a la base de datos.

        Args:
            scan (Scan): Objeto Scan a crear.

        Raises:
            SQLAlchemyError: En caso de error durante la inserción.
        """
        self._check_session()
        try:
            self.session.add(scan)
            self.session.commit()
            self.logger.info(f"Se creó un nuevo escaneo con ID {scan.id}")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al crear escaneo: {err}")
            raise

    #==============================================================
    # RETRIEVE
    #==============================================================
    def get_scan_by_id(self, scan_id: int) -> Optional[Scan]:
        """
        Obtiene un objeto Scan dado su ID.

        Args:
            scan_id (int): ID del escaneo a obtener.

        Returns:
            Optional[Scan]: Objeto Scan si existe, None si no.
        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            scan = self.session.query(Scan).filter(Scan.id == scan_id).one_or_none()
            self.logger.info(f"Se obtuvo el escaneo con ID {scan_id} de la base de datos.")
            return scan
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener escaneo por ID: {err}")
            raise

    def get_next_scan_id(self) -> int:
        """
        Obtiene el próximo ID disponible para un nuevo escaneo.

        Returns:
            int: Próximo ID disponible.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            result = self.session.execute(text("SELECT AUTO_INCREMENT FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'Scan';"))
            next_id = result.scalar_one()
            self.logger.info(f"Próximo ID disponible para Scan: {next_id}")
            return next_id
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener próximo ID para Scan: {err}")
            raise

    #==============================================================
    # UPDATE
    #==============================================================
    def update_scan(self, scan: Scan) -> None:
        """
        Actualiza la información de un Scan existente.

        Args:
            scan (Scan): Objeto Scan con los datos actualizados.

        Raises:
            SQLAlchemyError: En caso de error durante la actualización.
        """
        self._check_session()
        try:
            existing_scan = self.session.query(Scan).filter(Scan.id == scan.id).one_or_none()
            if existing_scan:
                existing_scan.target = scan.target
                existing_scan.started_at = scan.started_at
                self.session.commit()
                self.logger.info(f"Se actualizó la información del escaneo con ID {scan.id}.")
            else:
                self.logger.warning(f"No se encontró escaneo con ID {scan.id} para actualizar.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al actualizar escaneo: {err}")
            raise

    #==============================================================
    # DELETE
    #==============================================================
    def delete_scan(self, scan: Scan) -> None:
        """
        Elimina un Scan existente.

        Args:
            scan (Scan): Objeto Scan a eliminar.

        Raises:
            SQLAlchemyError: En caso de error durante la eliminación.
        """
        self._check_session()
        try:
            existing_scan = self.session.query(Scan).filter(Scan.id == scan.id).one_or_none()
            if existing_scan:
                self.session.delete(existing_scan)
                self.session.commit()
                self.logger.info(f"Se eliminó el escaneo con ID {scan.id} de la base de datos.")
            else:
                self.logger.warning(f"No se encontró escaneo con ID {scan.id} para eliminar.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al eliminar escaneo: {err}")
            raise


class NmapDBManager(ScanDBManager):
    """
    Gestor específico para operaciones relacionadas con escaneos Nmap y puertos.
    
    Gestiona:
    - Puertos (Port)
    - Escaneos Nmap (NmapScan)
    - Puertos objetivo (TargetPort)
    - Puertos abiertos (OpenPort)
    
    Métodos CRUD para Port:
        - port_exists(port_id: int) -> bool
        - port_exists_by_protocol(protocol: str) -> bool
        - create_port(port: Port) -> None
        - get_port_by_id(port_id: int) -> Optional[Port]
        - get_port_by_protocol(protocol: str) -> Optional[Port]
        - get_all_ports() -> List[Port]
        - update_port(port: Port) -> None
        - delete_port(port: Port) -> None
        - get_or_create_port(protocol: str) -> Port
    
    Métodos CRUD para NmapScan:
        - nmap_scan_exists(scan_id: int) -> bool
        - create_nmap_scan(scan: NmapScan) -> None
        - get_nmap_scan_by_id(scan_id: int) -> Optional[NmapScan]
        - get_all_nmap_scans() -> List[NmapScan]
        - get_nmap_scans_by_user(user_id: int) -> List[NmapScan]
        - update_nmap_scan(scan: NmapScan) -> None
        - delete_nmap_scan(scan: NmapScan) -> None
    
    Métodos para gestionar relaciones:
        - add_target_port(scan: NmapScan, port: Port) -> None
        - add_target_ports(scan: NmapScan, ports: List[Port]) -> None
        - remove_target_port(scan: NmapScan, port: Port) -> None
        - add_open_port(scan: NmapScan, port: Port, reason: str) -> None
        - remove_open_port(scan: NmapScan, port: Port) -> None
        - get_target_ports(scan: NmapScan) -> List[Port]
        - get_open_ports(scan: NmapScan) -> List[OpenPort]
    """

    # ============================================================
    # MÉTODOS PARA PORT - EXISTS
    # ============================================================
    
    def port_exists(self, port_id: int) -> bool:
        """
        Verifica si existe un puerto con el ID indicado.

        Args:
            port_id (int): ID del puerto a buscar.

        Returns:
            bool: True si existe, False en caso contrario.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            exists = self.session.query(Port).filter(Port.id == port_id).count() > 0
            self.logger.info(f"Verificación de existencia del puerto con ID '{port_id}': {exists}")
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia del puerto: {err}")
            raise

    def port_exists_by_protocol(self, protocol: str) -> bool:
        """
        Verifica si existe un puerto con el protocolo indicado.

        Args:
            protocol (str): Protocolo del puerto (ej: "80/tcp", "443/tcp").

        Returns:
            bool: True si existe, False en caso contrario.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            exists = self.session.query(Port).filter(Port.protocol == protocol).count() > 0
            self.logger.info(f"Verificación de existencia del puerto '{protocol}': {exists}")
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia del puerto: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA PORT - CREATE
    # ============================================================
    
    def create_port(self, port: Port) -> None:
        """
        Añade un nuevo puerto a la base de datos.

        Args:
            port (Port): Objeto Port a crear.

        Raises:
            SQLAlchemyError: En caso de error durante la inserción.
        """
        self._check_session()
        try:
            self.session.add(port)
            self.session.commit()
            self.logger.info(f"Se creó un nuevo puerto: {port.protocol} con ID {port.id}")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al crear puerto: {err}")
            raise

    def get_or_create_port(self, protocol: str) -> Port:
        """
        Obtiene un puerto por su protocolo, o lo crea si no existe.
        Útil para evitar duplicados.

        Args:
            protocol (str): Protocolo del puerto (ej: "80/tcp").

        Returns:
            Port: Objeto Port existente o recién creado.

        Raises:
            SQLAlchemyError: En caso de error en la operación.
        """
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

    # ============================================================
    # MÉTODOS PARA PORT - RETRIEVE
    # ============================================================
    
    def get_port_by_id(self, port_id: int) -> Optional[Port]:
        """
        Obtiene un puerto por su ID.

        Args:
            port_id (int): ID del puerto a obtener.

        Returns:
            Optional[Port]: Objeto Port si existe, None si no.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            port = self.session.query(Port).filter(Port.id == port_id).one_or_none()
            self.logger.info(f"Se obtuvo el puerto con ID {port_id} de la base de datos.")
            return port
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener puerto por ID: {err}")
            raise

    def get_port_by_protocol(self, protocol: str) -> Optional[Port]:
        """
        Obtiene un puerto por su protocolo.

        Args:
            protocol (str): Protocolo del puerto (ej: "80/tcp").

        Returns:
            Optional[Port]: Objeto Port si existe, None si no.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            port = self.session.query(Port).filter(Port.protocol == protocol).one_or_none()
            if port:
                self.logger.info(f"Se obtuvo el puerto '{protocol}' con ID {port.id}.")
            else:
                self.logger.info(f"No se encontró puerto con protocolo '{protocol}'.")
            return port
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener puerto por protocolo: {err}")
            raise

    def get_all_ports(self) -> List[Port]:
        """
        Obtiene todos los puertos existentes.

        Returns:
            List[Port]: Lista de todos los objetos Port.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            ports = self.session.query(Port).all()
            self.logger.info(f"Se obtuvieron {len(ports)} puertos de la base de datos.")
            return ports
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener todos los puertos: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA PORT - UPDATE
    # ============================================================
    
    def update_port(self, port: Port) -> None:
        """
        Actualiza la información de un puerto existente.

        Args:
            port (Port): Objeto Port con los datos actualizados.

        Raises:
            SQLAlchemyError: En caso de error durante la actualización.
        """
        self._check_session()
        try:
            existing_port = self.session.query(Port).filter(Port.id == port.id).one_or_none()
            if existing_port:
                existing_port.protocol = port.protocol
                self.session.commit()
                self.logger.info(f"Se actualizó la información del puerto con ID {port.id}.")
            else:
                self.logger.warning(f"No se encontró puerto con ID {port.id} para actualizar.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al actualizar puerto: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA PORT - DELETE
    # ============================================================
    
    def delete_port(self, port: Port) -> None:
        """
        Elimina un puerto existente.

        Args:
            port (Port): Objeto Port a eliminar.

        Raises:
            SQLAlchemyError: En caso de error durante la eliminación.
        """
        self._check_session()
        try:
            existing_port = self.session.query(Port).filter(Port.id == port.id).one_or_none()
            if existing_port:
                self.session.delete(existing_port)
                self.session.commit()
                self.logger.info(f"Se eliminó el puerto '{port.protocol}' con ID {port.id}.")
            else:
                self.logger.warning(f"No se encontró puerto con ID {port.id} para eliminar.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al eliminar puerto: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA NMAPSCAN - EXISTS
    # ============================================================
    
    def nmap_scan_exists(self, scan_id: int) -> bool:
        """
        Verifica si existe un escaneo Nmap con el ID indicado.

        Args:
            scan_id (int): ID del escaneo a buscar.

        Returns:
            bool: True si existe, False en caso contrario.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            exists = self.session.query(NmapScan).filter(NmapScan.id == scan_id).count() > 0
            self.logger.info(f"Verificación de existencia del escaneo Nmap con ID '{scan_id}': {exists}")
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia del escaneo Nmap: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA NMAPSCAN - CREATE
    # ============================================================
    
    def create_nmap_scan(self, scan) -> None:
        """
        Añade un nuevo escaneo Nmap a la base de datos.

        Args:
            scan (NmapScan): Objeto NmapScan a crear.

        Raises:
            SQLAlchemyError: En caso de error durante la inserción.
        """
        self._check_session()
        try:
            self.session.add(scan)
            self.session.commit()
            self.logger.info(f"Se creó un nuevo escaneo Nmap con ID {scan.id} para target '{scan.target}'")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al crear escaneo Nmap: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA NMAPSCAN - RETRIEVE
    # ============================================================
    
    def get_nmap_scan_by_id(self, scan_id: int):
        """
        Obtiene un escaneo Nmap por su ID.

        Args:
            scan_id (int): ID del escaneo a obtener.

        Returns:
            Optional[NmapScan]: Objeto NmapScan si existe, None si no.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            scan = self.session.query(NmapScan).filter(NmapScan.id == scan_id).one_or_none()
            self.logger.info(f"Se obtuvo el escaneo Nmap con ID {scan_id}.")
            return scan
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener escaneo Nmap por ID: {err}")
            raise

    def get_all_nmap_scans(self) -> List:
        """
        Obtiene todos los escaneos Nmap existentes.

        Returns:
            List[NmapScan]: Lista de todos los escaneos Nmap.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            scans = self.session.query(NmapScan).all()
            self.logger.info(f"Se obtuvieron {len(scans)} escaneos Nmap de la base de datos.")
            return scans
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener todos los escaneos Nmap: {err}")
            raise

    def get_nmap_scans_by_user(self, user_id: int) -> List:
        """
        Obtiene todos los escaneos Nmap de un usuario específico.

        Args:
            user_id (int): ID del usuario.

        Returns:
            List[NmapScan]: Lista de escaneos Nmap del usuario.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            scans = self.session.query(NmapScan).filter(NmapScan.user_id == user_id).all()
            self.logger.info(f"Se obtuvieron {len(scans)} escaneos Nmap del usuario con ID {user_id}.")
            return scans
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener escaneos Nmap por usuario: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA NMAPSCAN - UPDATE
    # ============================================================
    
    def update_nmap_scan(self, scan) -> None:
        """
        Actualiza la información de un escaneo Nmap existente.

        Args:
            scan (NmapScan): Objeto NmapScan con los datos actualizados.

        Raises:
            SQLAlchemyError: En caso de error durante la actualización.
        """
        self._check_session()
        try:
            existing_scan = self.session.query(NmapScan).filter(NmapScan.id == scan.id).one_or_none()
            if existing_scan:
                existing_scan.target = scan.target
                existing_scan.started_at = scan.started_at
                self.session.commit()
                self.logger.info(f"Se actualizó el escaneo Nmap con ID {scan.id}.")
            else:
                self.logger.warning(f"No se encontró escaneo Nmap con ID {scan.id} para actualizar.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al actualizar escaneo Nmap: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA NMAPSCAN - DELETE
    # ============================================================
    
    def delete_nmap_scan(self, scan) -> None:
        """
        Elimina un escaneo Nmap existente.

        Args:
            scan (NmapScan): Objeto NmapScan a eliminar.

        Raises:
            SQLAlchemyError: En caso de error durante la eliminación.
        """
        self._check_session()
        try:
            existing_scan = self.session.query(NmapScan).filter(NmapScan.id == scan.id).one_or_none()
            if existing_scan:
                self.session.delete(existing_scan)
                self.session.commit()
                self.logger.info(f"Se eliminó el escaneo Nmap con ID {scan.id}.")
            else:
                self.logger.warning(f"No se encontró escaneo Nmap con ID {scan.id} para eliminar.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al eliminar escaneo Nmap: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA GESTIONAR RELACIONES - TARGET PORTS
    # ============================================================
    
    def add_target_port(self, scan, port: Port) -> None:
        """
        Añade un puerto objetivo a un escaneo Nmap.

        Args:
            scan (NmapScan): Escaneo al que añadir el puerto.
            port (Port): Puerto a añadir como objetivo.

        Raises:
            SQLAlchemyError: En caso de error durante la operación.
        """
        self._check_session()
        try:
            if port not in scan.target_ports:
                scan.target_ports.append(port)
                self.session.commit()
                self.logger.info(f"Puerto '{port.protocol}' añadido como objetivo al escaneo {scan.id}.")
            else:
                self.logger.info(f"Puerto '{port.protocol}' ya está en los objetivos del escaneo {scan.id}.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al añadir puerto objetivo: {err}")
            raise

    def add_target_ports(self, scan, ports: List[Port]) -> None:
        """
        Añade múltiples puertos objetivo a un escaneo Nmap.

        Args:
            scan (NmapScan): Escaneo al que añadir los puertos.
            ports (List[Port]): Lista de puertos a añadir como objetivos.

        Raises:
            SQLAlchemyError: En caso de error durante la operación.
        """
        self._check_session()
        try:
            added = 0
            for port in ports:
                if port not in scan.target_ports:
                    scan.target_ports.append(port)
                    added += 1
            
            self.session.commit()
            self.logger.info(f"Se añadieron {added} puertos objetivo al escaneo {scan.id}.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al añadir puertos objetivo: {err}")
            raise

    def remove_target_port(self, scan, port: Port) -> None:
        """
        Elimina un puerto objetivo de un escaneo Nmap.

        Args:
            scan (NmapScan): Escaneo del que eliminar el puerto.
            port (Port): Puerto a eliminar de los objetivos.

        Raises:
            SQLAlchemyError: En caso de error durante la operación.
        """
        self._check_session()
        try:
            if port in scan.target_ports:
                scan.target_ports.remove(port)
                self.session.commit()
                self.logger.info(f"Puerto '{port.protocol}' eliminado de los objetivos del escaneo {scan.id}.")
            else:
                self.logger.warning(f"Puerto '{port.protocol}' no está en los objetivos del escaneo {scan.id}.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al eliminar puerto objetivo: {err}")
            raise

    def get_target_ports(self, scan) -> List[Port]:
        """
        Obtiene todos los puertos objetivo de un escaneo Nmap.

        Args:
            scan (NmapScan): Escaneo del que obtener los puertos objetivo.

        Returns:
            List[Port]: Lista de puertos objetivo del escaneo.
        """
        self._check_session()
        try:
            ports = scan.target_ports
            self.logger.info(f"Se obtuvieron {len(ports)} puertos objetivo del escaneo {scan.id}.")
            return ports
        except Exception as err:
            self.logger.error(f"Error al obtener puertos objetivo: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA GESTIONAR RELACIONES - OPEN PORTS
    # ============================================================
    
    def add_open_port(self, scan, port: Port, reason: str) -> None:
        """
        Marca un puerto como abierto en un escaneo Nmap.

        Args:
            scan (NmapScan): Escaneo en el que marcar el puerto.
            port (Port): Puerto a marcar como abierto.
            reason (str): Razón por la que el puerto está abierto (ej: "syn-ack").

        Raises:
            SQLAlchemyError: En caso de error durante la operación.
        """
        self._check_session()
        try:

            
            # Verificar si ya existe
            existing = self.session.query(OpenPort).filter(
                OpenPort.port_id == port.id,
                OpenPort.nmap_scan_id == scan.id
            ).first()
            
            if existing:
                self.logger.info(f"Puerto '{port.protocol}' ya está marcado como abierto en el escaneo {scan.id}.")
                return
            
            open_port = OpenPort(
                port_id=port.id,
                nmap_scan_id=scan.id,
                reason=reason
            )
            self.session.add(open_port)
            self.session.commit()
            self.logger.info(f"Puerto '{port.protocol}' marcado como abierto en escaneo {scan.id} (razón: {reason}).")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al añadir puerto abierto: {err}")
            raise

    def remove_open_port(self, scan, port: Port) -> None:
        """
        Elimina la marca de puerto abierto de un escaneo Nmap.

        Args:
            scan (NmapScan): Escaneo del que eliminar el puerto abierto.
            port (Port): Puerto a eliminar de los puertos abiertos.

        Raises:
            SQLAlchemyError: En caso de error durante la operación.
        """
        self._check_session()
        try:
            
            open_port = self.session.query(OpenPort).filter(
                OpenPort.port_id == port.id,
                OpenPort.nmap_scan_id == scan.id
            ).first()
            
            if open_port:
                self.session.delete(open_port)
                self.session.commit()
                self.logger.info(f"Puerto '{port.protocol}' eliminado de puertos abiertos del escaneo {scan.id}.")
            else:
                self.logger.warning(f"Puerto '{port.protocol}' no está en los puertos abiertos del escaneo {scan.id}.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al eliminar puerto abierto: {err}")
            raise

    def get_open_ports(self, scan) -> List:
        """
        Obtiene todos los puertos abiertos de un escaneo Nmap.

        Args:
            scan (NmapScan): Escaneo del que obtener los puertos abiertos.

        Returns:
            List[OpenPort]: Lista de objetos OpenPort del escaneo.
        """
        self._check_session()
        try:
            open_ports = scan.open_ports_relation
            self.logger.info(f"Se obtuvieron {len(open_ports)} puertos abiertos del escaneo {scan.id}.")
            return open_ports
        except Exception as err:
            self.logger.error(f"Error al obtener puertos abiertos: {err}")
            raise


class NiktoDBManager(ScanDBManager):
    """
    Gestor específico para operaciones relacionadas con escaneos Nikto e incidentes.
    
    Gestiona:
    - Incidentes Nikto (NiktoIncident)
    - Escaneos Nikto (NiktoScan)
    - Relación entre escaneos e incidentes (ScanIncident)
    
    Métodos CRUD para NiktoIncident:
        - nikto_incident_exists(incident_id: int) -> bool
        - create_nikto_incident(incident: NiktoIncident) -> None
        - get_nikto_incident_by_id(incident_id: int) -> Optional[NiktoIncident]
        - get_all_nikto_incidents() -> List[NiktoIncident]
        - update_nikto_incident(incident: NiktoIncident) -> None
        - delete_nikto_incident(incident: NiktoIncident) -> None
    
    Métodos CRUD para NiktoScan:
        - nikto_scan_exists(scan_id: int) -> bool
        - create_nikto_scan(scan: NiktoScan) -> None
        - get_nikto_scan_by_id(scan_id: int) -> Optional[NiktoScan]
        - get_all_nikto_scans() -> List[NiktoScan]
        - get_nikto_scans_by_user(user_id: int) -> List[NiktoScan]
        - update_nikto_scan(scan: NiktoScan) -> None
        - delete_nikto_scan(scan: NiktoScan) -> None
    
    Métodos para gestionar relaciones:
        - add_incident(scan: NiktoScan, incident: NiktoIncident) -> None
        - add_incidents(scan: NiktoScan, incidents: List[NiktoIncident]) -> None
        - remove_incident(scan: NiktoScan, incident: NiktoIncident) -> None
        - get_scan_incidents(scan: NiktoScan) -> List[NiktoIncident]
    """

    # ============================================================
    # MÉTODOS PARA NIKTOINCIDENT - EXISTS
    # ============================================================
    def nikto_incident_exists(self, incident_id: int) -> bool:
        """
        Verifica si existe un incidente Nikto con el ID indicado.

        Args:
            incident_id (int): ID del incidente a buscar.

        Returns:
            bool: True si existe, False en caso contrario.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            exists = self.session.query(NiktoIncident).filter(NiktoIncident.id == incident_id).count() > 0
            self.logger.info(f"Verificación de existencia del incidente Nikto con ID '{incident_id}': {exists}")
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia del incidente Nikto: {err}")
            raise


    def nikto_incident_exists_with_desc(self, incident_desc: str) -> bool:
        """
        Verifica si existe un incidente Nikto con el ID indicado.

        Args:
            incident_id (int): ID del incidente a buscar.

        Returns:
            bool: True si existe, False en caso contrario.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            exists = self.session.query(NiktoIncident).filter(NiktoIncident.description == incident_desc).count() > 0
            self.logger.info(f"Verificación de existencia del incidente Nikto con ID '{incident_desc}': {exists}")
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia del incidente Nikto: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA NIKTOINCIDENT - CREATE
    # ============================================================
    def create_nikto_incident(self, incident: NiktoIncident) -> None:
        """
        Añade un nuevo incidente Nikto a la base de datos.

        Args:
            incident (NiktoIncident): Objeto NiktoIncident a crear.

        Raises:
            SQLAlchemyError: En caso de error durante la inserción.
        """
        self._check_session()
        try:
            self.session.add(incident)
            self.session.commit()
            self.logger.info(f"Se creó un nuevo incidente Nikto con ID {incident.id}")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al crear incidente Nikto: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA NIKTOINCIDENT - RETRIEVE
    # ============================================================
    def get_nikto_incident_by_id(self, incident_id: int) -> Optional[NiktoIncident]:
        """
        Obtiene un incidente Nikto por su ID.

        Args:
            incident_id (int): ID del incidente a obtener.

        Returns:
            Optional[NiktoIncident]: Objeto NiktoIncident si existe, None si no.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            incident = self.session.query(NiktoIncident).filter(NiktoIncident.id == incident_id).one_or_none()
            self.logger.info(f"Se obtuvo el incidente Nikto con ID {incident_id}.")
            return incident
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener incidente Nikto por ID: {err}")
            raise

    def get_nikto_incident_by_description(self, incident_description: str) -> Optional[NiktoIncident]:
        """
        Obtiene un incidente Nikto por su ID.

        Args:
            incident_id (int): ID del incidente a obtener.

        Returns:
            Optional[NiktoIncident]: Objeto NiktoIncident si existe, None si no.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            incident = self.session.query(NiktoIncident).filter(NiktoIncident.description == incident_description).one_or_none()
            self.logger.info(f"Se obtuvo el incidente Nikto con ID {incident_description}.")
            return incident
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener incidente Nikto por ID: {err}")
            raise

    def get_all_nikto_incidents(self) -> List[NiktoIncident]:
        """
        Obtiene todos los incidentes Nikto existentes.

        Returns:
            List[NiktoIncident]: Lista de todos los objetos NiktoIncident.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            incidents = self.session.query(NiktoIncident).all()
            self.logger.info(f"Se obtuvieron {len(incidents)} incidentes Nikto de la base de datos.")
            return incidents
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener todos los incidentes Nikto: {err}")
            raise

    def get_or_create_nikto_incident(self, incident: NiktoIncident):
        """"
        Obtiene un puerto por su protocolo, o lo crea si no existe.
        Útil para evitar duplicados.

        Args:
            protocol (str): Protocolo del puerto (ej: "80/tcp").

        Returns:
            Port: Objeto Port existente o recién creado.

        Raises:
            SQLAlchemyError: En caso de error en la operación.
        """
        self._check_session()
        try:
            new_incident = self.get_nikto_incident_by_description(incident.description) #type: ignore
            if new_incident:
                self.logger.info(f"Incidente '{new_incident}' ya existe, reutilizando.")
                return new_incident
            
            self.create_nikto_incident(incident)
            self.logger.info(f"Incidente '{incident.description}' creado con ID {incident.id}")
            return incident
        except SQLAlchemyError as err:
            self.logger.error(f"Error en get_or_create_port: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA NIKTOINCIDENT - UPDATE
    # ============================================================
    def update_nikto_incident(self, incident: NiktoIncident) -> None:
        """
        Actualiza la información de un incidente Nikto existente.

        Args:
            incident (NiktoIncident): Objeto NiktoIncident con los datos actualizados.

        Raises:
            SQLAlchemyError: En caso de error durante la actualización.
        """
        self._check_session()
        try:
            existing_incident = self.session.query(NiktoIncident).filter(NiktoIncident.id == incident.id).one_or_none()
            if existing_incident:
                self.session.commit()
                self.logger.info(f"Se actualizó el incidente Nikto con ID {incident.id}.")
            else:
                self.logger.warning(f"No se encontró incidente Nikto con ID {incident.id} para actualizar.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al actualizar incidente Nikto: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA NIKTOINCIDENT - DELETE
    # ============================================================
    def delete_nikto_incident(self, incident: NiktoIncident) -> None:
        """
        Elimina un incidente Nikto existente.

        Args:
            incident (NiktoIncident): Objeto NiktoIncident a eliminar.

        Raises:
            SQLAlchemyError: En caso de error durante la eliminación.
        """
        self._check_session()
        try:
            existing_incident = self.session.query(NiktoIncident).filter(NiktoIncident.id == incident.id).one_or_none()
            if existing_incident:
                self.session.delete(existing_incident)
                self.session.commit()
                self.logger.info(f"Se eliminó el incidente Nikto con ID {incident.id}.")
            else:
                self.logger.warning(f"No se encontró incidente Nikto con ID {incident.id} para eliminar.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al eliminar incidente Nikto: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA NIKTOSCAN - EXISTS
    # ============================================================
    def nikto_scan_exists(self, scan_id: int) -> bool:
        """
        Verifica si existe un escaneo Nikto con el ID indicado.

        Args:
            scan_id (int): ID del escaneo a buscar.

        Returns:
            bool: True si existe, False en caso contrario.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            exists = self.session.query(NiktoScan).filter(NiktoScan.id == scan_id).count() > 0
            self.logger.info(f"Verificación de existencia del escaneo Nikto con ID '{scan_id}': {exists}")
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia del escaneo Nikto: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA NIKTOSCAN - CREATE
    # ============================================================
    def create_nikto_scan(self, scan: NiktoScan) -> None:
        """
        Añade un nuevo escaneo Nikto a la base de datos.

        Args:
            scan (NiktoScan): Objeto NiktoScan a crear.

        Raises:
            SQLAlchemyError: En caso de error durante la inserción.
        """
        self._check_session()
        try:
            self.session.add(scan)
            self.session.commit()
            self.logger.info(f"Se creó un nuevo escaneo Nikto con ID {scan.id} para target '{scan.target}'")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al crear escaneo Nikto: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA NIKTOSCAN - RETRIEVE
    # ============================================================
    def get_nikto_scan_by_id(self, scan_id: int) -> Optional[NiktoScan]:
        """
        Obtiene un escaneo Nikto por su ID.

        Args:
            scan_id (int): ID del escaneo a obtener.

        Returns:
            Optional[NiktoScan]: Objeto NiktoScan si existe, None si no.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            scan = self.session.query(NiktoScan).filter(NiktoScan.id == scan_id).one_or_none()
            self.logger.info(f"Se obtuvo el escaneo Nikto con ID {scan_id}.")
            return scan
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener escaneo Nikto por ID: {err}")
            raise

    def get_all_nikto_scans(self) -> List[NiktoScan]:
        """
        Obtiene todos los escaneos Nikto existentes.

        Returns:
            List[NiktoScan]: Lista de todos los escaneos Nikto.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            scans = self.session.query(NiktoScan).all()
            self.logger.info(f"Se obtuvieron {len(scans)} escaneos Nikto de la base de datos.")
            return scans
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener todos los escaneos Nikto: {err}")
            raise

    def get_nikto_scans_by_user(self, user_id: int) -> List[NiktoScan]:
        """
        Obtiene todos los escaneos Nikto de un usuario específico.

        Args:
            user_id (int): ID del usuario.

        Returns:
            List[NiktoScan]: Lista de escaneos Nikto del usuario.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """
        self._check_session()
        try:
            scans = self.session.query(NiktoScan).filter(NiktoScan.user_id == user_id).all()
            self.logger.info(f"Se obtuvieron {len(scans)} escaneos Nikto del usuario con ID {user_id}.")
            return scans
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener escaneos Nikto por usuario: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA NIKTOSCAN - UPDATE
    # ============================================================
    def update_nikto_scan(self, scan: NiktoScan) -> None:
        """
        Actualiza la información de un escaneo Nikto existente.

        Args:
            scan (NiktoScan): Objeto NiktoScan con los datos actualizados.

        Raises:
            SQLAlchemyError: En caso de error durante la actualización.
        """
        self._check_session()
        try:
            existing_scan = self.session.query(NiktoScan).filter(NiktoScan.id == scan.id).one_or_none()
            if existing_scan:
                existing_scan.target = scan.target
                existing_scan.started_at = scan.started_at
                self.session.commit()
                self.logger.info(f"Se actualizó el escaneo Nikto con ID {scan.id}.")
            else:
                self.logger.warning(f"No se encontró escaneo Nikto con ID {scan.id} para actualizar.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al actualizar escaneo Nikto: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA NIKTOSCAN - DELETE
    # ============================================================
    def delete_nikto_scan(self, scan: NiktoScan) -> None:
        """
        Elimina un escaneo Nikto existente.

        Args:
            scan (NiktoScan): Objeto NiktoScan a eliminar.

        Raises:
            SQLAlchemyError: En caso de error durante la eliminación.
        """
        self._check_session()
        try:
            existing_scan = self.session.query(NiktoScan).filter(NiktoScan.id == scan.id).one_or_none()
            if existing_scan:
                self.session.delete(existing_scan)
                self.session.commit()
                self.logger.info(f"Se eliminó el escaneo Nikto con ID {scan.id}.")
            else:
                self.logger.warning(f"No se encontró escaneo Nikto con ID {scan.id} para eliminar.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al eliminar escaneo Nikto: {err}")
            raise

    # ============================================================
    # MÉTODOS PARA GESTIONAR RELACIONES - INCIDENTS
    # ============================================================
    def add_incident(self, scan: NiktoScan, incident: NiktoIncident) -> None:
        """
        Añade un incidente a un escaneo Nikto.

        Args:
            scan (NiktoScan): Escaneo al que añadir el incidente.
            incident (NiktoIncident): Incidente a añadir.

        Raises:
            SQLAlchemyError: En caso de error durante la operación.
        """
        self._check_session()
        try:
            if incident not in scan.incidents:
                scan.incidents.append(incident)
                self.session.commit()
                self.logger.info(f"Incidente con ID {incident.id} añadido al escaneo Nikto {scan.id}.")
            else:
                self.logger.info(f"Incidente con ID {incident.id} ya está asociado al escaneo Nikto {scan.id}.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al añadir incidente: {err}")
            raise

    def add_incidents(self, scan: NiktoScan, incidents: List[NiktoIncident]) -> None:
        """
        Añade múltiples incidentes a un escaneo Nikto.

        Args:
            scan (NiktoScan): Escaneo al que añadir los incidentes.
            incidents (List[NiktoIncident]): Lista de incidentes a añadir.

        Raises:
            SQLAlchemyError: En caso de error durante la operación.
        """
        self._check_session()
        try:
            added = 0
            for incident in incidents:
                if incident not in scan.incidents:
                    scan.incidents.append(incident)
                    added += 1
            
            self.session.commit()
            self.logger.info(f"Se añadieron {added} incidentes al escaneo Nikto {scan.id}.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al añadir incidentes: {err}")
            raise

    def remove_incident(self, scan: NiktoScan, incident: NiktoIncident) -> None:
        """
        Elimina un incidente de un escaneo Nikto.

        Args:
            scan (NiktoScan): Escaneo del que eliminar el incidente.
            incident (NiktoIncident): Incidente a eliminar.

        Raises:
            SQLAlchemyError: En caso de error durante la operación.
        """
        self._check_session()
        try:
            if incident in scan.incidents:
                scan.incidents.remove(incident)
                self.session.commit()
                self.logger.info(f"Incidente con ID {incident.id} eliminado del escaneo Nikto {scan.id}.")
            else:
                self.logger.warning(f"Incidente con ID {incident.id} no está asociado al escaneo Nikto {scan.id}.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al eliminar incidente: {err}")
            raise

    def get_scan_incidents(self, scan: NiktoScan) -> List[NiktoIncident]:
        """
        Obtiene todos los incidentes de un escaneo Nikto.

        Args:
            scan (NiktoScan): Escaneo del que obtener los incidentes.

        Returns:
            List[NiktoIncident]: Lista de incidentes del escaneo.
        """
        self._check_session()
        try:
            incidents = scan.incidents
            self.logger.info(f"Se obtuvieron {len(incidents)} incidentes del escaneo Nikto {scan.id}.")
            return incidents
        except Exception as err:
            self.logger.error(f"Error al obtener incidentes del escaneo: {err}")
            raise