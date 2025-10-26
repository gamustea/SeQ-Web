import mysql.connector
from src.misc.configread import ConfigReader
from src.misc.logging import SecOpsLogger
from typing import List, Any
from src.model.users import Person, User

class NonEstablishedConnectionException(Exception):
    """
    Excepción personalizada para indicar que la conexión a la base de datos no está establecida.
    """
    pass

class DBManager():
    """
    Clase para gestionar la conexión y operaciones con la base de datos MySQL.
    """

    def __init__(self):
        """
        Inicializa el gestor de la base de datos leyendo las credenciales desde el archivo de configuración.
        """
        reader = ConfigReader()
        (
            self.username, 
            self.password, 
            self.host, 
            self.database
        ) = reader.get_db_crendetials()
        self.connection = None
        self.cursor = None
        self.logger = SecOpsLogger(name=__name__).get_logger()

    def connect(self):
        """Establece una conexión a la base de datos MySQL."""
        self.connection = mysql.connector.connect(
            host=self.host,
            user=self.username,
            password=self.password,
            database=self.database
        )
        self.cursor = self.connection.cursor(dictionary=True)
        self.logger.info("Conexión a la base de datos exitosa.")

    def disconnect(self):
        """
        Cierra la conexión a la base de datos MySQL.
        """
        if self.cursor is not None:
            self.cursor.close()
            self.logger.info("Cursor de la base de datos cerrado.")
        if self.connection is not None and self.connection.is_connected():
            self.connection.close()
            self.logger.info("Desconexión de la base de datos exitosa.")
        else:
            self.logger.info("La conexión ya estaba cerrada.")

class UserDBManager(DBManager):
    """
    Clase para gestionar operaciones específicas de usuarios en la base de datos.
    """

    def get_all_people(self) -> List[Person]:
        """
        Obtiene todos los usuarios de la tabla Persona.
        """
        if self.cursor is not None:
            QUERY = "SELECT * FROM Persona"
            self.cursor.execute(QUERY)
            self.logger.info("Se obtuvieron todos los usuarios de la base de datos.")

            results = tuple(self.cursor.fetchall())
            people = []
            for row in results:
                user = Person(
                    id=row['id'], # type: ignore
                    name=row['nombre'], # type: ignore
                    surname=row['apellido'], # type: ignore
                    email=row['email'], # type: ignore
                    date_created=row['fechaAlta'] # type: ignore
                )
                people.append(user)

            return people
        else:
            raise NonEstablishedConnectionException("La conexión a la base de datos no está establecida.")
        

    def get_person_by_id(self, person_id: int) -> Any:
        """
        Obtiene un usuario específico por su ID.
        """

        if self.cursor is not None:
            QUERY = "SELECT * FROM Persona WHERE id = %s"
            self.cursor.execute(QUERY, (person_id,))
            self.logger.info(f"Se obtuvo el usuario con ID {person_id} de la base de datos.")

            row = self.cursor.fetchone()
            if row:
                person = Person(
                    id=row['id'], # type: ignore
                    name=row['nombre'], # type: ignore
                    surname=row['apellido'], # type: ignore
                    email=row['email'], # type: ignore
                    date_created=row['fechaAlta'] # type: ignore
                )
                return person
            else:
                return None
        
        else:
            raise NonEstablishedConnectionException("La conexión a la base de datos no está establecida.")


    def get_all_users(self) -> List[User]:
        """
        Obtiene todos los usuarios de la tabla Usuario.
        """

        if self.cursor is not None:
            QUERY = "SELECT * FROM Usuario"
            self.cursor.execute(QUERY)
            self.logger.info("Se obtuvieron todos los usuarios de la base de datos.")

            results = self.cursor.fetchall()
            users = []
            for row in results:
                user = User(
                    id=row['id'], # type: ignore
                    username=row['username'], # type: ignore
                    person=self.get_person_by_id(row['idPersona']) # type: ignore
                )
                users.append(user)

            return users
        
        else:
            raise NonEstablishedConnectionException("La conexión a la base de datos no está establecida.")
