import unittest
from typing import Optional
from src.model import Person, User, Scan, Base
from src.persistence.dbmanaging import UserDBManager, ScanDBManager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime


class TestUserDBManager(unittest.TestCase):
    def setUp(self, database_url: str = "sqlite:///:memory:") -> None:
         # Crea el engine apuntando a la base en memoria
        self.engine = create_engine(database_url, echo=True)
        # Crea la sesión vinculada al engine en memoria
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.session: Session = SessionLocal()

        # Aquí debes crear las tablas, si usas ORM declarativo, ejemplo:
        from src.model import Base  # Asumiendo que Base es tu declarative_base()
        Base.metadata.create_all(bind=self.engine)
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


class TestScanDBManager(unittest.TestCase):
    def setUp(self):
        # Configura la base de datos en memoria para pruebas
        self.engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(self.engine)
        SessionLocal = sessionmaker(bind=self.engine)
        self.session = SessionLocal()
        
        # Crea un usuario para cumplir la FK user_id en Scan
        self.test_person = Person(first_name="Test", last_name="User", email="anemail@somewhere.com")
        self.test_user = User(username="testuser", password="testpass", person=self.test_person)
        self.session.add(self.test_person)
        self.session.add(self.test_user)
        self.session.commit()
        
        # Instancia del ScanDBManager con la sesión de prueba
        self.dbmanager = ScanDBManager(self.session)
        
        # Objeto Scan base para usar en tests
        self.scan = Scan(
            target="example.com",
            started_at=datetime.now(),
            user_id=self.test_user.id,
        )
    
    def tearDown(self):
        self.session.close()
    
    def test_create_scan_and_exists(self):
        self.dbmanager.create_scan(self.scan)
        exists = self.dbmanager.scan_exists(self.scan.id)
        self.assertTrue(exists)

    def test_get_scan_by_id(self):
        self.dbmanager.create_scan(self.scan)
        scan_fetched = self.dbmanager.get_scan_by_id(self.scan.id)
        self.assertIsNotNone(scan_fetched)
        self.assertEqual(scan_fetched.target, self.scan.target)

    def test_update_scan(self):
        self.dbmanager.create_scan(self.scan)
        self.scan.target = "updated.com"
        self.dbmanager.update_scan(self.scan)
        updated_scan = self.dbmanager.get_scan_by_id(self.scan.id)
        self.assertEqual(updated_scan.target, "updated.com")

    def test_delete_scan(self):
        self.dbmanager.create_scan(self.scan)
        self.assertTrue(self.dbmanager.scan_exists(self.scan.id))
        self.dbmanager.delete_scan(self.scan)
        self.assertFalse(self.dbmanager.scan_exists(self.scan.id))
