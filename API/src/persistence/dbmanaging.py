from sqlalchemy import text
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from typing import List, Optional

from src.misc.logging import SecOpsLogger
from src.model import Person, User
from src.misc.configread import ConfigReader
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
import urllib.parse

(USERNAME, PASSWORD, HOST, DBNAME) = ConfigReader().get_db_crendetials()
DEFAULT_DATABASE_URL = f"mysql+pymysql://gabriel:06No2004@localhost/SecOps"



class DBManager:
    """Gestor de sesión para base de datos usando SQLAlchemy ORM."""

    def __init__(self, session: Optional[Session] = None):
        if session is None:
            engine = create_engine(DEFAULT_DATABASE_URL)
            SessionLocal = sessionmaker(bind=engine)
            self.session = SessionLocal()
        else:
            self.session = session

        self.logger = SecOpsLogger(name=__name__).get_logger()

    def _check_session(self):
        if self.session is None:
            raise Exception("La sesión de base de datos no está establecida.")

    def _refresh_db(self) -> None:
        """Vacía las tablas especificadas sin borrar la estructura."""

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
    """Gestor ORM para operaciones de User y Person."""

    def user_exists(self, username: str) -> bool:
        self._check_session()
        try:
            exists = self.session.query(User).filter(User.username == username).count() > 0
            self.logger.info(f"Verificación de existencia del User '{username}': {exists}")
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia de User: {err}")
            raise

    def person_exists(self, person_id: int) -> bool:
        self._check_session()
        try:
            exists = self.session.query(Person).filter(Person.id == person_id).count() > 0
            self.logger.info(f"Verificación de existencia de la Person con ID '{person_id}': {exists}")
            return exists
        except SQLAlchemyError as err:
            self.logger.error(f"Error al verificar existencia de Person: {err}")
            raise

    def create_person(self, person: Person) -> None:
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
        self._check_session()
        try:
            if not self.person_exists(user.person_id): #type: ignore
                self.create_person(user.person)
            self.session.add(user)
            self.session.commit()
            self.logger.info(f"Se creó un nuevo User de sistema: {user.username} con ID {user.id}")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al crear User: {err}")
            raise

    def get_all_people(self) -> List[Person]:
        self._check_session()
        try:
            people = self.session.query(Person).all()
            self.logger.info("Se obtuvieron todos los Users de la base de datos.")
            return people
        except SQLAlchemyError as err:
            self.logger.error(f"Error al obtener todas las Persons: {err}")
            raise

    def get_person_by_id(self, person_id: int) -> Optional[Person]:
        self._check_session()
        try:
            person = self.session.query(Person).filter(Person.id == person_id).one_or_none()
            self.logger.info(f"Se obtuvo el User con ID {person_id} de la base de datos.")
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

    def update_person(self, person: Person) -> None:
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
        self._check_session()
        try:
            existing_user = self.session.query(User).filter(User.id == user.id).one_or_none()
            if existing_user:
                existing_user.username = user.username
                existing_user.id = user.id
                self.session.commit()
                self.logger.info(f"Se actualizó la información del User con ID {user.id}.")
            else:
                self.logger.warning(f"No se encontró User con ID {user.id} para actualizar.")
        except SQLAlchemyError as err:
            self.session.rollback()
            self.logger.error(f"Error al actualizar User: {err}")
            raise

    def delete_user(self, user: User) -> None:
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


class NmapDBManager(DBManager):
    """Clase para gestionar operaciones específicas de escaneos Nmap en la base de datos."""
    pass
