
import mysql.connector
from misc.configread import ConfigReader

class DBManager():
    """
    Clase para gestionar la conexión y operaciones con la base de datos MySQL.
    """

    def __init__(self):
        """
        Inicializa el gestor de la base de datos leyendo las credenciales desde el archivo de configuración.
        """
        reader = ConfigReader()
        
        (self.username, 
         self.password, 
         self.host, 
         self.database) = reader.get_db_crendetials()
        self.connection = None
        self.cursor = None
        

    def connect(self):
        """Establece una conexión a la base de datos MySQL."""
        self.connection = mysql.connector.connect(
            host="localhost",
            user="tu_usuario",
            password="tu_contraseña",
            database="nombre_basedatos"
        )
        self.cursor = self.connection.cursor()


    def disconnect(self):
        """
        Cierra la conexión a la base de datos MySQL.
        """
        if self.connection is not None and self.connection.is_connected():
            self.connection.close()
            print("Desconexión de la base de datos exitosa.")
        else:
            print("La conexión ya estaba cerrada.")
        
