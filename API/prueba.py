from src.logic.secrets import Encoder
from src.logic.managers import UserManager, NiktoScanManager, NmapScanManager

user = UserManager().get_user_by_id(1)
manager = NiktoScanManager(user)
manager.run_scan("testphp.vulnweb.com")
