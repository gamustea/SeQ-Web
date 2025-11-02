import unittest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.model import Base, Person, User, Scan, NmapScan, NiktoScan, OpenVASScan, Port, OpenPort
from src.persistence.dbmanaging import UserDBManager, ScanDBManager, NmapDBManager


class TestScanDBManager(unittest.TestCase):
    """
    Test suite para ScanDBManager usando SQLite en memoria.
    """

    def setUp(self):
        """
        Configura el entorno de prueba antes de cada test.
        Crea una base de datos SQLite en memoria con datos de prueba.
        """
        # Crear engine SQLite en memoria con echo para ver queries SQL (opcional)
        self.engine = create_engine("sqlite:///:memory:", echo=False)
        
        # Crear todas las tablas definidas en el modelo
        Base.metadata.create_all(self.engine)
        
        # Crear sesión
        SessionLocal = sessionmaker(bind=self.engine)
        self.session = SessionLocal()

        # Crear datos de prueba: Person y User
        self.person = Person(
            first_name="Test",
            last_name="User",
            email="test@example.com",
            created_at=datetime.now()
        )
        
        self.user = User(
            username="testuser",
            password="testpass",
            person=self.person
        )
        
        # Agregar y commitear person y user
        self.session.add_all([self.person, self.user])
        self.session.commit()
        
        # Refrescar para obtener IDs generados
        self.session.refresh(self.person)
        self.session.refresh(self.user)

        # Crear instancia del DBManager
        self.dbmanager = ScanDBManager(session=self.session)

        # Crear escaneo NmapScan de prueba
        self.scan = NmapScan(
            target="192.168.1.1",
            started_at=datetime.now(),
            user=self.user  # Usar objeto, no ID
        )
        
        self.session.add(self.scan)
        self.session.commit()
        self.session.refresh(self.scan)

    def tearDown(self):
        """
        Limpia el entorno después de cada test.
        Cierra la sesión y elimina todas las tablas.
        """
        self.session.close()
        Base.metadata.drop_all(self.engine)
        self.engine.dispose()

    # ============================================================
    # Tests para Scan
    # ============================================================
    
    def test_scan_exists(self):
        """Verifica que un scan existente se detecte correctamente."""
        self.assertTrue(self.dbmanager.scan_exists(self.scan.id))
        self.assertFalse(self.dbmanager.scan_exists(9999))

    def test_get_scan_by_id(self):
        """Verifica la obtención de un scan por ID."""
        scan = self.dbmanager.get_scan_by_id(self.scan.id)
        self.assertIsNotNone(scan)
        self.assertEqual(scan.target, "192.168.1.1")
        self.assertEqual(scan.scan_type, "nmap")
        self.assertIsInstance(scan, NmapScan)

    def test_get_scan_by_id_not_found(self):
        """Verifica que devuelve None si el scan no existe."""
        scan = self.dbmanager.get_scan_by_id(9999)
        self.assertIsNone(scan)

    def test_update_scan(self):
        """Verifica la actualización de un scan."""
        self.scan.target = "10.0.0.1"
        self.dbmanager.update_scan(self.scan)
        
        updated_scan = self.dbmanager.get_scan_by_id(self.scan.id)
        self.assertEqual(updated_scan.target, "10.0.0.1")

    def test_delete_scan(self):
        """Verifica la eliminación de un scan."""
        scan_id = self.scan.id
        self.dbmanager.delete_scan(self.scan)
        
        self.assertFalse(self.dbmanager.scan_exists(scan_id))

    def test_create_scan(self):
        """Verifica la creación de un nuevo scan."""
        new_scan = NmapScan(
            target="172.16.0.1",
            started_at=datetime.now(),
            user=self.user
        )
        
        self.dbmanager.create_scan(new_scan)
        self.assertIsNotNone(new_scan.id)
        self.assertTrue(self.dbmanager.scan_exists(new_scan.id))

    # ============================================================
    # Tests para diferentes tipos de Scan (Polimorfismo)
    # ============================================================
    
    def test_create_nikto_scan(self):
        """Verifica la creación de un NiktoScan."""
        nikto_scan = NiktoScan(
            target="http://example.com",
            started_at=datetime.now(),
            user=self.user
        )
        
        self.session.add(nikto_scan)
        self.session.commit()
        self.session.refresh(nikto_scan)
        
        retrieved = self.dbmanager.get_scan_by_id(nikto_scan.id)
        self.assertIsInstance(retrieved, NiktoScan)
        self.assertEqual(retrieved.scan_type, "nikto")

    def test_create_openvas_scan(self):
        """Verifica la creación de un OpenVASScan."""
        openvas_scan = OpenVASScan(
            target="192.168.1.100",
            started_at=datetime.now(),
            user=self.user
        )
        
        self.session.add(openvas_scan)
        self.session.commit()
        self.session.refresh(openvas_scan)
        
        retrieved = self.dbmanager.get_scan_by_id(openvas_scan.id)
        self.assertIsInstance(retrieved, OpenVASScan)
        self.assertEqual(retrieved.scan_type, "openvas")

    # ============================================================
    # Tests para relaciones (NmapScan con Ports)
    # ============================================================
    
    def test_nmap_scan_with_target_ports(self):
        """Verifica la relación NmapScan con puertos objetivo."""
        # Crear puertos
        port1 = Port(protocol="80/tcp")
        port2 = Port(protocol="443/tcp")
        
        self.session.add_all([port1, port2])
        self.session.commit()
        
        # Asociar puertos al scan
        self.scan.target_ports.append(port1)
        self.scan.target_ports.append(port2)
        self.session.commit()
        
        # Verificar
        retrieved = self.dbmanager.get_scan_by_id(self.scan.id)
        self.assertEqual(len(retrieved.target_ports), 2)
        protocols = [p.protocol for p in retrieved.target_ports]
        self.assertIn("80/tcp", protocols)
        self.assertIn("443/tcp", protocols)

    def test_nmap_scan_with_open_ports(self):
        """Verifica la relación NmapScan con puertos abiertos."""
        # Crear puerto
        port = Port(protocol="22/tcp")
        self.session.add(port)
        self.session.commit()
        
        # Crear entrada en OpenPort
        open_port = OpenPort(
            port_id=port.id,
            nmap_scan_id=self.scan.id,
            reason="syn-ack"
        )
        self.session.add(open_port)
        self.session.commit()
        
        # Verificar
        retrieved = self.dbmanager.get_scan_by_id(self.scan.id)
        self.assertEqual(len(retrieved.open_ports_relation), 1)
        self.assertEqual(retrieved.open_ports_relation[0].reason, "syn-ack")
        self.assertEqual(retrieved.open_ports_relation[0].port.protocol, "22/tcp")


class TestUserDBManager(unittest.TestCase):
    """
    Test suite para UserDBManager.
    """
    
    def setUp(self):
        """Configura el entorno de prueba."""
        self.engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(self.engine)
        SessionLocal = sessionmaker(bind=self.engine)
        self.session = SessionLocal()
        
        self.dbmanager = UserDBManager(session=self.session)
        
        # Crear datos de prueba
        self.person1 = Person(
            first_name="John",
            last_name="Doe",
            email="john@example.com",
            created_at=datetime.now()
        )
        
        self.user1 = User(
            username="johndoe",
            password="securepass123",
            person=self.person1
        )
        
        self.session.add_all([self.person1, self.user1])
        self.session.commit()
        self.session.refresh(self.person1)
        self.session.refresh(self.user1)

    def tearDown(self):
        """Limpia el entorno después de cada test."""
        self.session.close()
        Base.metadata.drop_all(self.engine)
        self.engine.dispose()

    # ============================================================
    # Tests para Person
    # ============================================================
    
    def test_person_exists(self):
        """Verifica que una persona existente se detecte."""
        self.assertTrue(self.dbmanager.person_exists(self.person1.id))
        self.assertFalse(self.dbmanager.person_exists(9999))

    def test_create_person(self):
        """Verifica la creación de una nueva persona."""
        person = Person(
            first_name="Jane",
            last_name="Smith",
            email="jane@example.com",
            created_at=datetime.now()
        )
        
        self.dbmanager.create_person(person)
        self.assertIsNotNone(person.id)
        self.assertTrue(self.dbmanager.person_exists(person.id))

    def test_get_person_by_id(self):
        """Verifica la obtención de una persona por ID."""
        person = self.dbmanager.get_person_by_id(self.person1.id)
        self.assertIsNotNone(person)
        self.assertEqual(person.first_name, "John")
        self.assertEqual(person.email, "john@example.com")

    def test_update_person(self):
        """Verifica la actualización de una persona."""
        self.person1.email = "newemail@example.com"
        self.dbmanager.update_person(self.person1)
        
        updated = self.dbmanager.get_person_by_id(self.person1.id)
        self.assertEqual(updated.email, "newemail@example.com")

    def test_delete_person(self):
        """Verifica la eliminación de una persona."""
        person_id = self.person1.id
        
        # Primero eliminar el user asociado
        self.dbmanager.delete_user(self.user1)
        # Luego la person
        self.dbmanager.delete_person(self.person1)
        
        self.assertFalse(self.dbmanager.person_exists(person_id))

    # ============================================================
    # Tests para User
    # ============================================================
    
    def test_user_exists(self):
        """Verifica que un usuario existente se detecte."""
        self.assertTrue(self.dbmanager.user_exists("johndoe"))
        self.assertFalse(self.dbmanager.user_exists("nonexistent"))

    def test_create_user(self):
        """Verifica la creación de un nuevo usuario."""
        person = Person(
            first_name="Alice",
            last_name="Wonder",
            email="alice@example.com",
            created_at=datetime.now()
        )
        
        user = User(
            username="alicewonder",
            password="alicepass",
            person=person
        )
        
        self.dbmanager.create_user(user)
        self.assertIsNotNone(user.id)
        self.assertTrue(self.dbmanager.user_exists("alicewonder"))

    def test_get_user_by_id(self):
        """Verifica la obtención de un usuario por ID."""
        user = self.dbmanager.get_user_by_id(self.user1.id)
        self.assertIsNotNone(user)
        self.assertEqual(user.username, "johndoe")

    def test_update_user(self):
        """Verifica la actualización de un usuario."""
        self.user1.password = "newpassword456"
        self.dbmanager.update_user(self.user1)
        
        updated = self.dbmanager.get_user_by_id(self.user1.id)
        self.assertEqual(updated.password, "newpassword456")

    def test_get_all_people(self):
        """Verifica la obtención de todas las personas."""
        people = self.dbmanager.get_all_people()
        self.assertGreaterEqual(len(people), 1)

    def test_get_all_users(self):
        """Verifica la obtención de todos los usuarios."""
        users = self.dbmanager.get_all_users()
        self.assertGreaterEqual(len(users), 1)
