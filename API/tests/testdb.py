import unittest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.model import Base, Person, User, Scan, NmapScan, NiktoScan, NiktoIncident, OpenVASScan, Port, OpenPort
from src.persistence.dbmanaging import UserDBManager, ScanDBManager, NmapDBManager, NiktoDBManager


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


class TestNiktoDBManager(unittest.TestCase):
    """
    Test suite para NiktoDBManager usando SQLite en memoria.
    """

    def setUp(self):
        """
        Configura el entorno de prueba antes de cada test.
        Crea una base de datos SQLite en memoria con datos de prueba.
        """
        # Crear engine SQLite en memoria
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
        self.dbmanager = NiktoDBManager(session=self.session)

        # Crear escaneo NiktoScan de prueba
        self.scan = NiktoScan(
            target="http://example.com",
            started_at=datetime.now(),
            user=self.user
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
    # Tests para NiktoScan - EXISTS
    # ============================================================
    
    def test_nikto_scan_exists(self):
        """Verifica que un scan Nikto existente se detecte correctamente."""
        self.assertTrue(self.dbmanager.nikto_scan_exists(self.scan.id))
        self.assertFalse(self.dbmanager.nikto_scan_exists(9999))

    # ============================================================
    # Tests para NiktoScan - CREATE
    # ============================================================
    
    def test_create_nikto_scan(self):
        """Verifica la creación de un nuevo escaneo Nikto."""
        new_scan = NiktoScan(
            target="http://testsite.com",
            started_at=datetime.now(),
            user=self.user
        )
        
        self.dbmanager.create_nikto_scan(new_scan)
        self.assertIsNotNone(new_scan.id)
        self.assertTrue(self.dbmanager.nikto_scan_exists(new_scan.id))

    # ============================================================
    # Tests para NiktoScan - RETRIEVE
    # ============================================================
    
    def test_get_nikto_scan_by_id(self):
        """Verifica la obtención de un scan Nikto por ID."""
        scan = self.dbmanager.get_nikto_scan_by_id(self.scan.id)
        self.assertIsNotNone(scan)
        self.assertEqual(scan.target, "http://example.com")
        self.assertEqual(scan.scan_type, "nikto")
        self.assertIsInstance(scan, NiktoScan)

    def test_get_nikto_scan_by_id_not_found(self):
        """Verifica que devuelve None si el scan Nikto no existe."""
        scan = self.dbmanager.get_nikto_scan_by_id(9999)
        self.assertIsNone(scan)

    def test_get_all_nikto_scans(self):
        """Verifica la obtención de todos los escaneos Nikto."""
        # Crear un segundo scan
        scan2 = NiktoScan(
            target="http://anothersite.com",
            started_at=datetime.now(),
            user=self.user
        )
        self.session.add(scan2)
        self.session.commit()
        
        scans = self.dbmanager.get_all_nikto_scans()
        self.assertGreaterEqual(len(scans), 2)
        self.assertTrue(all(isinstance(s, NiktoScan) for s in scans))

    def test_get_nikto_scans_by_user(self):
        """Verifica la obtención de escaneos Nikto por usuario."""
        # Crear otro usuario y scan
        person2 = Person(
            first_name="Another",
            last_name="User",
            email="another@example.com",
            created_at=datetime.now()
        )
        user2 = User(
            username="anotheruser",
            password="pass123",
            person=person2
        )
        self.session.add_all([person2, user2])
        self.session.commit()
        self.session.refresh(user2)
        
        scan2 = NiktoScan(
            target="http://user2site.com",
            started_at=datetime.now(),
            user=user2
        )
        self.session.add(scan2)
        self.session.commit()
        
        # Verificar scans del primer usuario
        user1_scans = self.dbmanager.get_nikto_scans_by_user(self.user.id)
        self.assertEqual(len(user1_scans), 1)
        self.assertEqual(user1_scans[0].user_id, self.user.id)
        
        # Verificar scans del segundo usuario
        user2_scans = self.dbmanager.get_nikto_scans_by_user(user2.id)
        self.assertEqual(len(user2_scans), 1)
        self.assertEqual(user2_scans[0].user_id, user2.id)

    # ============================================================
    # Tests para NiktoScan - UPDATE
    # ============================================================
    
    def test_update_nikto_scan(self):
        """Verifica la actualización de un scan Nikto."""
        self.scan.target = "http://updatedsite.com"
        self.dbmanager.update_nikto_scan(self.scan)
        
        updated_scan = self.dbmanager.get_nikto_scan_by_id(self.scan.id)
        self.assertEqual(updated_scan.target, "http://updatedsite.com")

    def test_update_nikto_scan_not_found(self):
        """Verifica que update maneje correctamente scans no existentes."""
        fake_scan = NiktoScan(
            target="http://fake.com",
            started_at=datetime.now(),
            user=self.user
        )
        fake_scan.id = 9999
        
        # No debería lanzar excepción, solo advertencia en log
        self.dbmanager.update_nikto_scan(fake_scan)

    # ============================================================
    # Tests para NiktoScan - DELETE
    # ============================================================
    
    def test_delete_nikto_scan(self):
        """Verifica la eliminación de un scan Nikto."""
        scan_id = self.scan.id
        self.dbmanager.delete_nikto_scan(self.scan)
        
        self.assertFalse(self.dbmanager.nikto_scan_exists(scan_id))

    def test_delete_nikto_scan_not_found(self):
        """Verifica que delete maneje correctamente scans no existentes."""
        fake_scan = NiktoScan(
            target="http://fake.com",
            started_at=datetime.now(),
            user=self.user
        )
        fake_scan.id = 9999
        
        # No debería lanzar excepción, solo advertencia en log
        self.dbmanager.delete_nikto_scan(fake_scan)

    # ============================================================
    # Tests para NiktoIncident - EXISTS
    # ============================================================
    
    def test_nikto_incident_exists(self):
        """Verifica que un incidente Nikto existente se detecte correctamente."""
        incident = NiktoIncident(
            url="/admin/",
            description="Directorio administrativo sin protección",
            discovered_at=datetime.now()
        )
        self.session.add(incident)
        self.session.commit()
        self.session.refresh(incident)
        
        self.assertTrue(self.dbmanager.nikto_incident_exists(incident.id))
        self.assertFalse(self.dbmanager.nikto_incident_exists(9999))

    # ============================================================
    # Tests para NiktoIncident - CREATE
    # ============================================================
    
    def test_create_nikto_incident(self):
        """Verifica la creación de un nuevo incidente Nikto."""
        incident = NiktoIncident(
            osvdb_id="OSVDB-3268",
            method="GET",
            url="/admin/",
            description="Directorio administrativo accesible",
            severity="medium",
            ip_address="192.168.1.100",
            port=80,
            references="https://cve.mitre.org/...",
            discovered_at=datetime.now()
        )
        
        self.dbmanager.create_nikto_incident(incident)
        self.assertIsNotNone(incident.id)
        self.assertTrue(self.dbmanager.nikto_incident_exists(incident.id))

    # ============================================================
    # Tests para NiktoIncident - RETRIEVE
    # ============================================================
    
    def test_get_nikto_incident_by_id(self):
        """Verifica la obtención de un incidente Nikto por ID."""
        incident = NiktoIncident(
            url="/test/",
            description="Test incident",
            discovered_at=datetime.now()
        )
        self.session.add(incident)
        self.session.commit()
        self.session.refresh(incident)
        
        retrieved = self.dbmanager.get_nikto_incident_by_id(incident.id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.id, incident.id)
        self.assertEqual(retrieved.url, "/test/")

    def test_get_nikto_incident_by_id_not_found(self):
        """Verifica que devuelve None si el incidente no existe."""
        incident = self.dbmanager.get_nikto_incident_by_id(9999)
        self.assertIsNone(incident)

    def test_get_all_nikto_incidents(self):
        """Verifica la obtención de todos los incidentes Nikto."""
        incident1 = NiktoIncident(
            url="/vuln1/",
            description="Vulnerabilidad 1",
            discovered_at=datetime.now()
        )
        incident2 = NiktoIncident(
            url="/vuln2/",
            description="Vulnerabilidad 2",
            discovered_at=datetime.now()
        )
        
        self.session.add_all([incident1, incident2])
        self.session.commit()
        
        incidents = self.dbmanager.get_all_nikto_incidents()
        self.assertGreaterEqual(len(incidents), 2)
        self.assertTrue(all(isinstance(i, NiktoIncident) for i in incidents))

    # ============================================================
    # Tests para NiktoIncident - UPDATE
    # ============================================================
    
    def test_update_nikto_incident(self):
        """Verifica la actualización de un incidente Nikto."""
        incident = NiktoIncident(
            url="/old/",
            description="Old description",
            discovered_at=datetime.now()
        )
        self.session.add(incident)
        self.session.commit()
        self.session.refresh(incident)
        
        # Crear otro scan para cambiar la relación
        scan2 = NiktoScan(
            target="http://another.com",
            started_at=datetime.now(),
            user=self.user
        )
        self.session.add(scan2)
        self.session.commit()
        self.session.refresh(scan2)
        
        self.dbmanager.update_nikto_incident(incident)
        
        updated = self.dbmanager.get_nikto_incident_by_id(incident.id)

    # ============================================================
    # Tests para NiktoIncident - DELETE
    # ============================================================
    
    def test_delete_nikto_incident(self):
        """Verifica la eliminación de un incidente Nikto."""
        incident = NiktoIncident(
            url="/delete/",
            description="To be deleted",
            discovered_at=datetime.now()
        )
        self.session.add(incident)
        self.session.commit()
        self.session.refresh(incident)
        
        incident_id = incident.id
        self.dbmanager.delete_nikto_incident(incident)
        
        self.assertFalse(self.dbmanager.nikto_incident_exists(incident_id))

    # ============================================================
    # Tests para relaciones (NiktoScan con NiktoIncident)
    # ============================================================
    
    def test_add_incident_to_scan(self):
        """Verifica añadir un incidente a un escaneo Nikto."""
        incident = NiktoIncident(
            url="/incident/",
            description="Test incident for relationship",
            discovered_at=datetime.now()
        )
        self.session.add(incident)
        self.session.commit()
        self.session.refresh(incident)
        
        self.dbmanager.add_incident(self.scan, incident)
        
        # Verificar que el incidente está asociado
        retrieved_scan = self.dbmanager.get_nikto_scan_by_id(self.scan.id)
        self.assertEqual(len(retrieved_scan.incidents), 1)
        self.assertEqual(retrieved_scan.incidents[0].id, incident.id)

    def test_add_incident_duplicate(self):
        """Verifica que no se dupliquen incidentes en un escaneo."""
        incident = NiktoIncident(
            url="/dup/",
            description="Duplicate test",
            discovered_at=datetime.now()
        )
        self.session.add(incident)
        self.session.commit()
        self.session.refresh(incident)
        
        # Añadir dos veces el mismo incidente
        self.dbmanager.add_incident(self.scan, incident)
        self.dbmanager.add_incident(self.scan, incident)
        
        retrieved_scan = self.dbmanager.get_nikto_scan_by_id(self.scan.id)
        self.assertEqual(len(retrieved_scan.incidents), 1)

    def test_add_multiple_incidents(self):
        """Verifica añadir múltiples incidentes a un escaneo Nikto."""
        incidents = [
            NiktoIncident(
                url=f"/vuln{i}/",
                description=f"Vulnerability {i}",
                discovered_at=datetime.now()
            )
            for i in range(1, 4)
        ]
        
        self.session.add_all(incidents)
        self.session.commit()
        
        self.dbmanager.add_incidents(self.scan, incidents)
        
        retrieved_scan = self.dbmanager.get_nikto_scan_by_id(self.scan.id)
        self.assertEqual(len(retrieved_scan.incidents), 3)

    def test_add_multiple_incidents_with_duplicates(self):
        """Verifica que add_incidents no añada duplicados."""
        incident1 = NiktoIncident(
            url="/inc1/",
            description="Incident 1",
            discovered_at=datetime.now()
        )
        incident2 = NiktoIncident(
            url="/inc2/",
            description="Incident 2",
            discovered_at=datetime.now()
        )
        
        self.session.add_all([incident1, incident2])
        self.session.commit()
        
        # Añadir primero incident1
        self.dbmanager.add_incident(self.scan, incident1)
        
        # Intentar añadir ambos (incident1 ya está)
        self.dbmanager.add_incidents(self.scan, [incident1, incident2])
        
        retrieved_scan = self.dbmanager.get_nikto_scan_by_id(self.scan.id)
        self.assertEqual(len(retrieved_scan.incidents), 2)

    def test_remove_incident_from_scan(self):
        """Verifica eliminar un incidente de un escaneo Nikto."""
        incident = NiktoIncident(
            url="/remove/",
            description="To be removed",
            discovered_at=datetime.now()
        )
        self.session.add(incident)
        self.session.commit()
        self.session.refresh(incident)
        
        # Añadir y luego eliminar
        self.dbmanager.add_incident(self.scan, incident)
        self.assertEqual(len(self.scan.incidents), 1)
        
        self.dbmanager.remove_incident(self.scan, incident)
        
        retrieved_scan = self.dbmanager.get_nikto_scan_by_id(self.scan.id)
        self.assertEqual(len(retrieved_scan.incidents), 0)

    def test_remove_incident_not_in_scan(self):
        """Verifica que remove_incident maneje correctamente incidentes no asociados."""
        incident = NiktoIncident(
            url="/notassoc/",
            description="Not associated",
            discovered_at=datetime.now()
        )
        self.session.add(incident)
        self.session.commit()
        self.session.refresh(incident)
        
        # Intentar eliminar sin haberlo añadido
        # No debería lanzar excepción, solo advertencia en log
        self.dbmanager.remove_incident(self.scan, incident)

    def test_get_scan_incidents(self):
        """Verifica obtener todos los incidentes de un escaneo."""
        incidents = [
            NiktoIncident(
                url=f"/get{i}/",
                description=f"Get incident {i}",
                discovered_at=datetime.now()
            )
            for i in range(1, 3)
        ]
        
        self.session.add_all(incidents)
        self.session.commit()
        
        self.dbmanager.add_incidents(self.scan, incidents)
        
        retrieved_incidents = self.dbmanager.get_scan_incidents(self.scan)
        self.assertEqual(len(retrieved_incidents), 2)
        incident_ids = [i.id for i in retrieved_incidents]
        self.assertIn(incidents[0].id, incident_ids)
        self.assertIn(incidents[1].id, incident_ids)

    def test_get_scan_incidents_empty(self):
        """Verifica obtener incidentes de un escaneo sin incidentes."""
        incidents = self.dbmanager.get_scan_incidents(self.scan)
        self.assertEqual(len(incidents), 0)

    # ============================================================
    # Tests de integración
    # ============================================================
    
    def test_full_workflow(self):
        """Test de flujo completo: crear scan, añadir incidentes, consultar y eliminar."""
        # 1. Crear scan
        scan = NiktoScan(
            target="http://fullworkflow.com",
            started_at=datetime.now(),
            user=self.user
        )
        self.dbmanager.create_nikto_scan(scan)
        
        # 2. Crear y añadir incidentes con todos los campos
        incidents = [
            NiktoIncident(
                osvdb_id=f"OSVDB-{1000+i}",
                method="GET",
                url=f"/workflow{i}/",
                description=f"Workflow vulnerability {i}",
                severity="high" if i == 0 else "medium",
                ip_address="192.168.1.100",
                port=80,
                references="https://cve.mitre.org/...",
                discovered_at=datetime.now()
            )
            for i in range(3)
        ]
        
        for inc in incidents:
            self.dbmanager.create_nikto_incident(inc)
        
        self.dbmanager.add_incidents(scan, incidents)
        
        # 3. Verificar
        retrieved = self.dbmanager.get_nikto_scan_by_id(scan.id)
        self.assertEqual(len(retrieved.incidents), 3)
        
        # Verificar campos del primer incidente
        first_incident = retrieved.incidents[0]
        self.assertIsNotNone(first_incident.osvdb_id)
        self.assertEqual(first_incident.method, "GET")
        self.assertIn(first_incident.severity, ["high", "medium"])
        
        # 4. Eliminar un incidente
        self.dbmanager.remove_incident(scan, incidents[0])
        retrieved = self.dbmanager.get_nikto_scan_by_id(scan.id)
        self.assertEqual(len(retrieved.incidents), 2)
        
        # 5. Eliminar el scan
        scan_id = scan.id
        self.dbmanager.delete_nikto_scan(scan)
        self.assertFalse(self.dbmanager.nikto_scan_exists(scan_id))