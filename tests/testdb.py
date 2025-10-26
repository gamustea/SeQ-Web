
from unittest import TestCase
from typing import List
from src.persistence.dbmanaging import UserDBManager, NonEstablishedConnectionException

class TestUserDBManager(TestCase):
    """
    Clase de prueba para gestionar operaciones específicas de usuarios en la base de datos.
    """
    def test_get_people(self) -> List:
        """
        Obtiene todos los usuarios de la base de datos.
        """
        
        db_manager = UserDBManager()
        db_manager.connect()
        try:
            results = db_manager.get_all_people()
            db_manager.logger.info(f"Se obtuvieron {len(results)} usuarios de la base de datos.")
            return results
        finally:
            db_manager.disconnect()


    def test_get_person_by_id(self, person_id: int) -> None:
        """
        Obtiene un usuario específico por su ID.
        """
        
        db_manager = UserDBManager()
        db_manager.connect()
        try:
            result = db_manager.get_person_by_id(person_id)
            if result:
                db_manager.logger.info(f"Se obtuvo el usuario con ID {person_id} de la base de datos.")
            else:
                db_manager.logger.info(f"No se encontró el usuario con ID {person_id} en la base de datos.")
            return result
        finally:
            db_manager.disconnect()


    def test_get_users(self) -> List:
        """
        Obtiene todos los usuarios de la base de datos.
        """
        
        db_manager = UserDBManager()
        db_manager.connect()
        try:
            results = db_manager.get_all_users()
            db_manager.logger.info(f"Se obtuvieron {len(results)} usuarios de la base de datos.")
            return results
        finally:
            db_manager.disconnect()