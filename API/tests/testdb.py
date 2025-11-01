import unittest
from typing import Optional
from src.model import Person, User  # Ajuste nombres de clases a español para correspondencia con ORM Python
from src.persistence.dbmanaging import UserDBManager

class TestUserDBManagerORM(unittest.TestCase):
    def setUp(self) -> None:
        self.dbmanager = UserDBManager()
        # Crear objetos Person pero no asignar relaciones todavía
        self.person1 = Person(first_name="Gabriel", last_name="Musteata", email="gamusteaunirioja.es")
        self.person2 = Person(first_name="Marcos", last_name="Prez", email="maparelosunirioja.es")

    def tearDown(self) -> None:
        self.dbmanager.session.close()

    def test_people(self) -> None:
        self.dbmanager._refresh_db()

        self.dbmanager.create_person(self.person1)
        self.dbmanager.create_person(self.person2)

        self.assertTrue(self.dbmanager.person_exists(self.person1.id))  # type: ignore
        self.assertTrue(self.dbmanager.person_exists(self.person2.id))  # type: ignore

        self.person1.email = "gmiganescugmail.com"  # type: ignore
        self.dbmanager.update_person(self.person1)

        p1: Optional[Person] = self.dbmanager.get_person_by_id(self.person1.id)  # type: ignore
        self.assertIsNotNone(p1)
        if p1:
            self.assertEqual(p1.email, "gmiganescugmail.com")

    def test_users(self) -> None:
        self.dbmanager._refresh_db()

        # Crear personas y añadirlas a la sesión explícitamente usando los métodos del dbmanager
        self.dbmanager.create_person(self.person1)
        self.dbmanager.create_person(self.person2)

        # Crear usuarios
        user1 = User(username="gabriel123", password="password")
        user2 = User(username="marcos456", password="password")

        # Añadir usuarios a la sesión explícitamente
        self.dbmanager.session.add(user1)
        self.dbmanager.session.add(user2)

        # Asignar la relación y asegurarse que las personas ya están en sesión
        user1.person = self.person1
        user2.person = self.person2

        # Confirmar cambios
        self.dbmanager.session.commit()

        self.assertTrue(self.dbmanager.user_exists(user1.username))  # type: ignore
        self.assertTrue(self.dbmanager.user_exists(user2.username))  # type: ignore

        # Actualizar username y email con objetos de la sesión
        user1.username = "gabrielnuevo"  # type: ignore
        self.person1.email = "gabrielnuevo@gmail.com"  # type: ignore
        user1.person = self.person1

        self.dbmanager.update_user(user1)
        self.dbmanager.update_person(self.person1)

        user1_from_db: Optional[User] = self.dbmanager.get_user_by_id(user1.id)  # type: ignore
        self.assertIsNotNone(user1_from_db)
        if user1_from_db:
            self.assertEqual(user1_from_db.username, "gabrielnuevo")
            self.assertEqual(user1_from_db.person.email, "gabrielnuevo@gmail.com")

        user2_from_db: Optional[User] = self.dbmanager.get_user_by_id(user2.id)  # type: ignore
        self.assertIsNotNone(user2_from_db)
        if user2_from_db:
            self.assertEqual(user2_from_db.username, "marcos456")
