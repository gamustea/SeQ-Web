from src.logic.managers import UserManager, NiktoScanManager

if __name__ == "__main__":
    # Prueba de creación de usuario
    user_manager = UserManager()
    user = user_manager.get_user_by_id(1)

    scan_manager = NiktoScanManager(user)
    scan_manager.run_scan(
        target_domain="https://emesa.com", 
        timeout=60
    )