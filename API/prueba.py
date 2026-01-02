from src.logic.secrets import Encoder
from src.logic.managers import UserManager, NiktoScanManager, NmapScanManager

user = UserManager().get_user_by_id(1)
nmap_manager = NmapScanManager(user)
nikto_manager = NiktoScanManager(user)

id = nmap_manager.run_scan("192.168.1.1", "1-1024")
is_finished = nmap_manager.is_scan_finished(id)
print(f"Escaneo Nmap finalizado: {is_finished}")


