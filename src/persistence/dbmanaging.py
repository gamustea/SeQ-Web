import mysql.connector
from mysql.connector import Error
from src.misc.configread import ConfigReader
from src.misc.logging import SecOpsLogger
from typing import List, Optional
from src.model.users import Person, User


class NonEstablishedConnectionException(Exception):
    """Excepción personalizada para indicar que la conexión a la base de datos no está establecida."""
    pass


class DBManager:
    """Clase para gestionar la conexión y operaciones con la base de datos MySQL mediante contexto."""

    def __init__(self):
        """Inicializa el gestor de la base de datos leyendo las credenciales desde el archivo de configuración."""
        reader = ConfigReader()
        (self.username, self.password, self.host, self.database) = reader.get_db_crendetials()
        self.connection = None
        self.cursor = None
        self.logger = SecOpsLogger(name=__name__).get_logger()

    def __enter__(self):
        """Permite el uso con 'with', establece la conexión automáticamente."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cierra la conexión y cursor automáticamente."""
        self.disconnect()

    def connect(self) -> None:
        """Establece una conexión a la base de datos MySQL."""
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                user=self.username,
                password=self.password,
                database=self.database
            )
            self.cursor = self.connection.cursor(dictionary=True)
            self.logger.info("Conexión a la base de datos exitosa.")
        except Error as err:
            self.logger.error(f"Error al conectar a la base de datos: {err}")
            raise

    def disconnect(self) -> None:
        """Cierra la conexión a la base de datos MySQL."""
        try:
            if self.cursor is not None:
                self.cursor.close()
                self.logger.info("Cursor de la base de datos cerrado.")
            if self.connection is not None and self.connection.is_connected():
                self.connection.close()
                self.logger.info("Desconexión de la base de datos exitosa.")
            else:
                self.logger.info("La conexión ya estaba cerrada.")
        except Error as err:
            self.logger.error(f"Error al desconectar de la base de datos: {err}")
            raise

    def _check_connection(self) -> None:
        """Verifica que la conexión y cursor estén establecidos, lanza excepción si no."""
        if self.cursor is None or self.connection is None or not self.connection.is_connected():
            raise NonEstablishedConnectionException("La conexión a la base de datos no está establecida.")

    def _validate_attrs(self):
        """Valida que la conexión y cursor no sean None."""
        if self.cursor is None or self.connection is None:
            raise NonEstablishedConnectionException("La conexión a la base de datos no está establecida.")


class UserDBManager(DBManager):
    """Clase para gestionar operaciones específicas de usuarios en la base de datos."""


    # EXISTENCE METHODS
    def user_exists(self, username: str) -> bool:
        self._validate_attrs()
        try:
            QUERY = "SELECT COUNT(*) AS count FROM Usuario WHERE username = %s"
            self.cursor.execute(QUERY, (username,)) #type: ignore
            result = self.cursor.fetchone() #type: ignore
            exists = result['count'] > 0  # type: ignore
            self.logger.info(f"Verificación de existencia del usuario '{username}': {exists}")
            return exists
        except Error as err:
            self.logger.error(f"Error al verificar existencia de usuario: {err}")
            raise


    def person_exists(self, person_id: int) -> bool:
        self._validate_attrs()
        try:
            QUERY = "SELECT COUNT(*) AS count FROM Persona WHERE id = %s"
            self.cursor.execute(QUERY, (person_id,)) #type: ignore
            result = self.cursor.fetchone() #type: ignore
            exists = result['count'] > 0  # type: ignore
            self.logger.info(f"Verificación de existencia de la persona con ID '{person_id}': {exists}")
            return exists
        except Error as err:
            self.logger.error(f"Error al verificar existencia de persona: {err}")
            raise


    # CREATE METHODS
    def create_person(self, person: Person) -> None:
        self._validate_attrs()
        try:
            QUERY = """
            INSERT INTO Persona (nombre, apellido, email, fechaAlta)
            VALUES (%s, %s, %s, %s)
            """
            VALUES = (person.name, person.surname, person.email, person.date_created)
            self.cursor.execute(QUERY, VALUES) #type: ignore
            self.connection.commit() #type: ignore
            person.id = self.cursor.lastrowid #type: ignore
            self.logger.info(f"Se creó un nuevo usuario: {person.name} {person.surname} con ID {person.id}")
        except Error as err:
            self.logger.error(f"Error al crear persona: {err}")
            self.connection.rollback() #type: ignore
            raise


    def create_user(self, user: User) -> None:
        self._validate_attrs()
        try:
            if not self.person_exists(user.person.id):
                self.create_person(user.person)

            QUERY = """
            INSERT INTO Usuario (username, idPersona)
            VALUES (%s, %s)
            """
            VALUES = (user.username, user.person.id)
            self.cursor.execute(QUERY, VALUES) #type: ignore
            self.connection.commit() #type: ignore
            user.id = self.cursor.lastrowid #type: ignore
            self.logger.info(f"Se creó un nuevo usuario de sistema: {user.username} con ID {user.id}")
        except Error as err:
            self.logger.error(f"Error al crear usuario: {err}")
            self.connection.rollback() #type: ignore
            raise


    # RETRIEVE METHODS
    def get_all_people(self) -> List[Person]:
        self._validate_attrs()
        try:
            QUERY = "SELECT * FROM Persona"
            self.cursor.execute(QUERY) #type: ignore
            self.logger.info("Se obtuvieron todos los usuarios de la base de datos.")
            results = tuple(self.cursor.fetchall()) #type: ignore
            people = [
                Person(
                    id=row['id'],  # type: ignore
                    name=row['nombre'],  # type: ignore
                    surname=row['apellido'],  # type: ignore
                    email=row['email'],  # type: ignore
                    date_created=row['fechaAlta']  # type: ignore
                )
                for row in results
            ]
            return people
        except Error as err:
            self.logger.error(f"Error al obtener todas las personas: {err}")
            raise


    def get_person_by_id(self, person_id: int) -> Optional[Person]:
        self._validate_attrs()
        try:
            QUERY = "SELECT * FROM Persona WHERE id = %s"
            self.cursor.execute(QUERY, (person_id,)) #type: ignore
            self.logger.info(f"Se obtuvo el usuario con ID {person_id} de la base de datos.")
            row = self.cursor.fetchone() #type: ignore
            if row:
                person = Person(
                    id=row['id'],  # type: ignore
                    name=row['nombre'],  # type: ignore
                    surname=row['apellido'],  # type: ignore
                    email=row['email'],  # type: ignore
                    date_created=row['fechaAlta']  # type: ignore
                )
                return person
            return None
        except Error as err:
            self.logger.error(f"Error al obtener persona por ID: {err}")
            raise


    def get_all_users(self) -> List[User]:
        self._validate_attrs()
        try:
            QUERY = "SELECT * FROM Usuario"
            self.cursor.execute(QUERY) #type: ignore
            self.logger.info("Se obtuvieron todos los usuarios de la base de datos.")
            results = self.cursor.fetchall() #type: ignore
            users = [
                User(
                    id=row['id'],  # type: ignore
                    username=row['username'],  # type: ignore
                    person=self.get_person_by_id(row['idPersona'])  # type: ignore
                )
                for row in results
            ]
            return users
        except Error as err:
            self.logger.error(f"Error al obtener todos los usuarios: {err}")
            raise


    def get_user_by_id(self, user_id: int) -> Optional[User]:
        self._validate_attrs()
        try:
            QUERY = "SELECT * FROM Usuario WHERE id = %s"
            self.cursor.execute(QUERY, (user_id,)) #type: ignore
            self.logger.info(f"Se obtuvo el usuario con ID {user_id} de la base de datos.")
            row = self.cursor.fetchone() #type: ignore
            if row:
                user = User(
                    id=row['id'],  # type: ignore
                    username=row['username'],  # type: ignore
                    person=self.get_person_by_id(row['idPersona'])  # type: ignore
                )
                return user
            return None
        except Error as err:
            self.logger.error(f"Error al obtener usuario por ID: {err}")
            raise


    # UPDATE METHODS
    def update_person(self, person: Person) -> None:
        self._validate_attrs()
        try:
            QUERY = """
            UPDATE Persona
            SET nombre = %s, apellido = %s, email = %s
            WHERE id = %s
            """
            VALUES = (person.name, person.surname, person.email, person.id)
            self.cursor.execute(QUERY, VALUES) #type: ignore
            self.connection.commit() #type: ignore
            self.logger.info(f"Se actualizó la información de la persona con ID {person.id}.")
        except Error as err:
            self.logger.error(f"Error al actualizar persona: {err}")
            self.connection.rollback() #type: ignore
            raise


    def update_user(self, user: User) -> None:
        self._validate_attrs()
        try:
            QUERY = """
            UPDATE Usuario
            SET username = %s, idPersona = %s
            WHERE id = %s
            """
            VALUES = (user.username, user.person.id, user.id)
            self.cursor.execute(QUERY, VALUES) #type: ignore
            self.connection.commit() #type: ignore
            self.logger.info(f"Se actualizó la información del usuario con ID {user.id}.")
        except Error as err:
            self.logger.error(f"Error al actualizar usuario: {err}")
            self.connection.rollback() #type: ignore
            raise


    # DELETE METHODS
    def delete_user(self, user: User) -> None:
        self._validate_attrs()
        try:
            QUERY = "DELETE FROM Usuario WHERE id = %s"
            self.cursor.execute(QUERY, (user.id,)) #type: ignore
            self.connection.commit() #type: ignore
            self.logger.info(f"Se eliminó el usuario con ID {user.id} de la base de datos.")
        except Error as err:
            self.logger.error(f"Error al eliminar usuario: {err}")
            self.connection.rollback() #type: ignore
            raise


    def delete_person(self, person: Person) -> None:
        self._validate_attrs()
        try:
            QUERY = "DELETE FROM Persona WHERE id = %s"
            self.cursor.execute(QUERY, (person.id,)) #type: ignore
            self.connection.commit() #type: ignore
            self.logger.info(f"Se eliminó la persona con ID {person.id} de la base de datos.")
        except Error as err:
            self.logger.error(f"Error al eliminar persona: {err}")
            self.connection.rollback() #type: ignore
            raise
