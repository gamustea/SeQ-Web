

from src.logic.managers import NmapScanManager, UserManager

user_manager = UserManager()
user = user_manager.get_user_by_id(1)

manager = NmapScanManager(user)
scan_id = manager.run_scan("127.0.0.1", "1-1024", timeout=300)
manager.cancel_scan(scan_id)