
from unittest import TestCase
from typing import List, Optional
from src.model.users import Person
from src.persistence.dbmanaging import UserDBManager, NonEstablishedConnectionException

class TestUserDBManager(TestCase):
    
    def __init__(self) -> None:
        super().__init__()
        self.db_manager = UserDBManager()

    def test_people(self) -> None:
        persona_1 = Person(
            name = "Gabriel", 
            surname = "Musteata", 
            email = "gamustea@unirioja.es"
        )

        persona_2 = Person(
            name = "Marcos",
            surname = "Pérez",
            email = "maparelos@unirioja.es",
        )

        try:
            self.db_manager.connect()
            self.db_manager.create_person(persona_1)
            self.db_manager.create_person(persona_2)

            self.assertTrue(self.db_manager.person_exists(persona_1.id), "La persona 1 debería existir en la base de datos.");
            self.assertTrue(self.db_manager.person_exists(persona_2.id), "La persona 1 debería existir en la base de datos.");
        except NonEstablishedConnectionException:
            raise AssertionError("Database connection could not be established.")