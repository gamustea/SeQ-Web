import json
from pathlib import Path
from typing import Optional
from enum import Enum


class DirectoryType(Enum):
    """Enumeración de tipos de directorios disponibles"""
    TEMP = "tempdir"
    LOG = "logdir"
    RESULT = "resultdir"
    RESOURCE = "resourcedir"

class ConfigReader:
    def __init__(self, configs_file: str = "API/src/config/SecConfig.json") -> None:
        self.configs_path = Path(configs_file).resolve()
    
    def read_configs(self) -> dict:
        with open(self.configs_path, "r") as config_file:
            configs = json.load(config_file)
        return configs
    
    def get_db_crendetials(self) -> tuple:
        configs = self.read_configs()
        username = configs["dbconfig"]["username"]
        password = configs["dbconfig"]["password"]
        host = configs["dbconfig"]["host"]
        database = configs["dbconfig"]["dbname"]
        return (username, password, host, database)
    
    def get_directory_of(self, directory_type: DirectoryType) -> str:
        """
        Obtiene la ruta del directorio especificado en el archivo de configuración.
        
        Args:
            directory_type: Tipo de directorio (DirectoryType.TEMP, .LOG, .RESULT, .RESOURCE)
        
        Returns:
            str: Ruta del directorio
        """
        configs = self.read_configs()
        directories = configs["directories"]
        
        dir_key = directory_type.value
        if dir_key not in directories:
            raise ValueError(f"Directorio '{dir_key}' no encontrado en la configuración.")
        
        return directories[dir_key]
