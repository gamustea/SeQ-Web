
from src.logic.userutilities import UserManager

print("Probando UserManager...")
user_manager = UserManager()
print("Verificando credenciales para usuario 'testuser' con contraseña 'password123'...")
is_valid = user_manager.verify_credentials("testuser", "password123")
print(f"¿Credenciales válidas? {is_valid}")
print("Verificando credenciales para usuario 'root' con contraseña 'root'...")
is_valid = user_manager.verify_credentials("root", "root")
print(f"¿Credenciales válidas? {is_valid}")