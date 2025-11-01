from sqlalchemy import text, create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError
from typing import List, Optional
import urllib.parse

from src.misc.logging import SecOpsLogger
from src.model import Person, User, Port, Scan, NmapScan
from src.misc.configread import ConfigReader


# Obtener credenciales para la conexión a la base de datos y construir la URL de conexión MySQL
(USERNAME, PASSWORD, HOST, DBNAME) = ConfigReader().get_db_crendetials()
DEFAULT_DATABASE_URL = f"mysql+pymysql://{USERNAME}:{urllib.parse.quote(PASSWORD)}@{HOST}/{DBNAME}"


class DBManager:
    """
    Gestor general para la sesión y operaciones básicas en la base de datos usando SQLAlchemy ORM.

    Atributos:
        session (Session): Sesión activa de SQLAlchemy para interactuar con la base de datos.
        logger (Logger): Logger personalizado para registrar eventos e incidencias.
    
    Métodos:
        __init__(session: Optional[Session] = None):
            Inicializa la sesión de base de datos. Si no se pasa una sesión, crea una a partir
            de la URL por defecto.

        _check_session():
            Verifica que la sesión esté establecida antes de realizar operaciones.

        _refresh_db():
            Vacía el contenido de tablas específicas sin borrar su estructura, útil para tests o reinicio de datos.
    """

    def __init__(self, session: Optional[Session] = None):
        """
        Constructor del gestor.

        Args:
            session (Optional[Session]): Sesión SQLAlchemy externa. Si es None, crea una interna.
        """
        if session is None:
            engine = create_engine(DEFAULT_DATABASE_URL)
            SessionLocal = sessionmaker(bind=engine)
            self.session = SessionLocal()
        else:
            self.session = session

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
            person_id (int): ID de la persona a buscar.

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
        Añade una nueva persona a la base de datos.

        Args:
            person (Person): Objeto Person a crear.

        Raises:
            SQLAlchemyError: En caso de error durante la inserción.
        """
        self._check_session()
        try:
            self.session.add(person)
            self.session.commit()
            self.logger.info(f"Se creó un nuevo User: {person.first_name} {person.last_name} con ID {person.id}")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al crear Person: {err}")
            raise

    def create_user(self, user: User) -> None:
        """
        Añade un nuevo usuario al sistema. Crea la Person relacionada si no existe.

        Args:
            user (User): Objeto User a crear, debe tener el atributo persona asociado.

        Raises:
            SQLAlchemyError: En caso de error durante la inserción.
        """
        self._check_session()
        try:
            if not self.person_exists(user.person_id):  # type: ignore
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
            self.logger.info("Se obtuvieron todos los Users de la base de datos.")
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
            self.logger.info(f"Se obtuvo el User con ID {person_id} de la base de datos.")
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
                existing_user.id = user.id  # Generalmente no cambia, pero se mantiene en la actualización
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
    Actualmente no implementada.
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


class NmapDBManager(DBManager):
    """
    Clase para gestionar operaciones específicas de escaneos Nmap en la base de datos.
    Actualmente no implementada.
    """

    #===============================================================
    #
    #===============================================================
    def port_exists(self, port_id: int) -> bool:
        """
        Verifica si existe un puerto con el número indicado.

        Args:
            port_number (int): Número de puerto a buscar.

        Returns:
            bool: True si existe, False en caso contrario.

        Raises:
            SQLAlchemyError: En caso de error en la consulta.
        """

        self._check_session()
        try:
            exists = self.session.query(Port).filter(Port.id == port_id).count() > 0
            self.logger.info(f"Verificación de existencia del puerto '{port_id}': {exists}")
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia del puerto: {err}")
            raise
