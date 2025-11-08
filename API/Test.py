from tests.testreader import TestReader
from tests.testdb import TestUserDBManager, TestScanDBManager, TestNiktoDBManager
from src.model import Person, User, NmapScan, Port, OpenPort
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.model import Person, User, NmapScan, Port, OpenPort, NiktoIncident, NiktoScan
from src.persistence.dbmanaging import UserDBManager, ScanDBManager

"""
Script de ejemplo para agregar usuarios y escaneos Nmap a la base de datos.

Muestra dos formas de hacerlo:
1. Usando los DBManagers (recomendado)
2. Usando la sesión directamente

Ejecutar: python ejemplo_agregar_datos.py
"""

from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.model import Person, User, NmapScan, Port, OpenPort
from src.persistence.dbmanaging import UserDBManager, ScanDBManager, NmapDBManager


def ejemplo_con_dbmanagers():
    """
    Ejemplo usando los DBManagers para operaciones CRUD.
    Esta es la forma recomendada ya que incluye logging y manejo de errores.
    """
    print("=" * 60)
    print("EJEMPLO 1: Usando DBManagers")
    print("=" * 60)
    
    user_manager = UserDBManager()
    scan_manager = ScanDBManager()
    nmap_manager = NmapDBManager()
    
    try:
        # --------------------------------------------------------
        # 1. Crear una nueva persona
        # --------------------------------------------------------
        nueva_persona = Person(
            first_name="María",
            last_name="González",
            email="maria.gonzalez@secops.com",
        )
        
        user_manager.create_person(nueva_persona)
        print(f"✓ Persona creada con ID: {nueva_persona.id}")
        
        # --------------------------------------------------------
        # 2. Crear un nuevo usuario asociado a la persona
        # --------------------------------------------------------
        nuevo_usuario = User(
            username="mgonzalez",
            password="hashed_password_here",  # En producción: usar bcrypt o similar
            person=nueva_persona  # Asociar directamente el objeto
        )
        
        user_manager.create_user(nuevo_usuario)
        print(f"✓ Usuario creado con ID: {nuevo_usuario.id}")
        
        # --------------------------------------------------------
        # 3. Crear un escaneo Nmap usando NmapDBManager
        # --------------------------------------------------------
        escaneo_nmap = NmapScan(
            target="192.168.1.0/24",
            user=nuevo_usuario  # Asociar el usuario
        )
        
        nmap_manager.create_nmap_scan(escaneo_nmap)
        print(f"✓ Escaneo Nmap creado con ID: {escaneo_nmap.id}")
        print(f"  - Target: {escaneo_nmap.target}")
        print(f"  - Tipo: {escaneo_nmap.scan_type}")
        print(f"  - Iniciado: {escaneo_nmap.started_at}")
        
        # --------------------------------------------------------
        # 4. Agregar puertos objetivo usando get_or_create_port
        # --------------------------------------------------------
        print("\n📌 Agregando puertos objetivo...")
        
        # Usar get_or_create_port para evitar duplicados
        puerto_80 = nmap_manager.get_or_create_port("80/tcp")
        puerto_443 = nmap_manager.get_or_create_port("443/tcp")
        puerto_22 = nmap_manager.get_or_create_port("22/tcp")
        puerto_25 = nmap_manager.get_or_create_port("25/tcp")
        
        # Añadir múltiples puertos objetivo de una vez
        nmap_manager.add_target_ports(escaneo_nmap, [puerto_80, puerto_443, puerto_22, puerto_25])
        
        print(f"✓ Agregados {len(nmap_manager.get_target_ports(escaneo_nmap))} puertos objetivo")
        
        # --------------------------------------------------------
        # 5. Simular resultado: marcar puertos como abiertos
        # --------------------------------------------------------
        print("\n🔓 Marcando puertos abiertos...")
        
        nmap_manager.add_open_port(escaneo_nmap, puerto_80, "syn-ack")
        nmap_manager.add_open_port(escaneo_nmap, puerto_443, "syn-ack")
        nmap_manager.add_open_port(escaneo_nmap, puerto_22, "syn-ack")
        
        print(f"✓ Marcados 3 puertos como abiertos")
        
        # --------------------------------------------------------
        # 6. Consultar datos creados usando los managers
        # --------------------------------------------------------
        print("\n" + "-" * 60)
        print("VERIFICACIÓN DE DATOS CREADOS:")
        print("-" * 60)
        
        # Verificar usuario
        usuario_recuperado = user_manager.get_user_by_id(nuevo_usuario.id)
        print(f"\n👤 Usuario recuperado:")
        print(f"  - Username: {usuario_recuperado.username}")
        print(f"  - Nombre completo: {usuario_recuperado.person.first_name} {usuario_recuperado.person.last_name}")
        print(f"  - Email: {usuario_recuperado.person.email}")
        
        # Verificar escaneo usando NmapDBManager
        scan_recuperado = nmap_manager.get_nmap_scan_by_id(escaneo_nmap.id)
        print(f"\n🔍 Escaneo recuperado:")
        print(f"  - ID: {scan_recuperado.id}")
        print(f"  - Target: {scan_recuperado.target}")
        print(f"  - Usuario: {scan_recuperado.user.username}")
        
        # Obtener puertos objetivo usando el manager
        puertos_objetivo = nmap_manager.get_target_ports(scan_recuperado)
        print(f"  - Puertos objetivo: {len(puertos_objetivo)}")
        for p in puertos_objetivo:
            print(f"    • {p.protocol}")
        
        # Obtener puertos abiertos usando el manager
        puertos_abiertos = nmap_manager.get_open_ports(scan_recuperado)
        print(f"  - Puertos abiertos: {len(puertos_abiertos)}")
        for op in puertos_abiertos:
            print(f"    • {op.port.protocol} - {op.reason}")
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        user_manager.session.rollback()
    finally:
        user_manager.session.close()

if __name__ == "__main__":

    testDBManager = TestUserDBManager()
    testDBManager.setUp()
    testDBManager.test_create_person()
    testDBManager.test_person_exists()
    testDBManager.test_update_person()
    testDBManager.test_delete_person()
    testDBManager.tearDown()

    testDBManager.setUp()
    testDBManager.test_create_user()
    testDBManager.test_user_exists()
    testDBManager.test_update_user()
    testDBManager.tearDown()

    testDBManager = TestScanDBManager()
    testDBManager.setUp()
    testDBManager.test_get_scan_by_id()
    testDBManager.test_create_scan()
    testDBManager.test_scan_exists()
    testDBManager.tearDown()

    print("INICIO DE TESTS - NiktoDBManager", "=")
    
    # Crear instancia de la clase de tests
    test_suite = TestNiktoDBManager()
    
    # Lista de todos los métodos de test
    test_methods = [
        # Tests de NiktoScan - EXISTS
        "test_nikto_scan_exists",
        
        # Tests de NiktoScan - CREATE
        "test_create_nikto_scan",
        
        # Tests de NiktoScan - RETRIEVE
        "test_get_nikto_scan_by_id",
        "test_get_nikto_scan_by_id_not_found",
        "test_get_all_nikto_scans",
        "test_get_nikto_scans_by_user",
        
        # Tests de NiktoScan - UPDATE
        "test_update_nikto_scan",
        "test_update_nikto_scan_not_found",
        
        # Tests de NiktoScan - DELETE
        "test_delete_nikto_scan",
        "test_delete_nikto_scan_not_found",
        
        # Tests de NiktoIncident - EXISTS
        "test_nikto_incident_exists",
        
        # Tests de NiktoIncident - CREATE
        "test_create_nikto_incident",
        
        # Tests de NiktoIncident - RETRIEVE
        "test_get_nikto_incident_by_id",
        "test_get_nikto_incident_by_id_not_found",
        "test_get_all_nikto_incidents",
        
        # Tests de NiktoIncident - UPDATE
        "test_update_nikto_incident",
        
        # Tests de NiktoIncident - DELETE
        "test_delete_nikto_incident",
        
        # Tests de Relaciones
        "test_add_incident_to_scan",
        "test_add_incident_duplicate",
        "test_add_multiple_incidents",
        "test_add_multiple_incidents_with_duplicates",
        "test_remove_incident_from_scan",
        "test_remove_incident_not_in_scan",
        "test_get_scan_incidents",
        "test_get_scan_incidents_empty",
        
        # Tests de Integración
        "test_full_workflow",
    ]
    
    results = {
        "passed": [],
        "failed": [],
        "errors": []
    }
    
    total_tests = len(test_methods)
    
    for i, test_name in enumerate(test_methods, 1):
        print(f"Test {i}/{total_tests}: {test_name}", "-")
        
        try:
            # setUp
            print("🔧 Ejecutando setUp()...")
            test_suite.setUp()
            print("   ✓ Base de datos en memoria creada")
            print("   ✓ Tablas creadas")
            print("   ✓ Datos de prueba insertados (Person, User, NiktoScan)")
            print("   ✓ DBManager inicializado\n")
            
            # Ejecutar test
            print(f"🧪 Ejecutando {test_name}()...")
            test_method = getattr(test_suite, test_name)
            test_method()
            print(f"   ✅ TEST PASSED\n")
            results["passed"].append(test_name)
            
        except AssertionError as e:
            print(f"   ❌ TEST FAILED: {str(e)}\n")
            results["failed"].append((test_name, str(e)))
            
        except Exception as e:
            print(f"   ⚠️  TEST ERROR: {str(e)}\n")
            results["errors"].append((test_name, str(e)))
            
        finally:
            # tearDown
            print("🧹 Ejecutando tearDown()...")
            try:
                test_suite.tearDown()
                print("   ✓ Sesión cerrada")
                print("   ✓ Tablas eliminadas")
                print("   ✓ Conexión cerrada")
            except Exception as e:
                print(f"   ⚠️  Error en tearDown: {str(e)}")
    
    # Resumen final
    print("RESUMEN DE EJECUCIÓN", "=")
    
    print(f"📊 Total de tests ejecutados: {total_tests}")
    print(f"✅ Tests exitosos: {len(results['passed'])} ({len(results['passed'])/total_tests*100:.1f}%)")
    print(f"❌ Tests fallidos: {len(results['failed'])} ({len(results['failed'])/total_tests*100:.1f}%)")
    print(f"⚠️  Errores: {len(results['errors'])} ({len(results['errors'])/total_tests*100:.1f}%)")
    
    if results["passed"]:
        print("\n✅ TESTS EXITOSOS:")
        for test_name in results["passed"]:
            print(f"   • {test_name}")
    
    if results["failed"]:
        print("\n❌ TESTS FALLIDOS:")
        for test_name, error in results["failed"]:
            print(f"   • {test_name}")
            print(f"     Error: {error}")
    
    if results["errors"]:
        print("\n⚠️  ERRORES:")
        for test_name, error in results["errors"]:
            print(f"   • {test_name}")
            print(f"     Error: {error}")
    
    print("\n" + "="*70)
    
    # Retornar código de salida
    if results["failed"] or results["errors"]:
        print("\n❌ Algunos tests fallaron o tuvieron errores")
    else:
        print("\n✅ Todos los tests pasaron exitosamente")




