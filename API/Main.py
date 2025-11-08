
import json
import threading
import time

from src.scanning.tasks import NmapScanTask, NiktoScanTask
from src.misc.configread import ConfigReader
from src.misc.conversion import JSONManager
from src.scanning.scanmanaging import NmapScanManager, NiktoScanManager

from src.persistence.dbmanaging import *
from src.model import *


if __name__ == "__main__":
    user_db_manager = UserDBManager()
    user: User = user_db_manager.get_user_by_id(1)

    manager = NiktoScanManager(user)
    scan = NiktoScan(
        target="http://testphp.vulnweb.com",
        user=user
    )
    manager._do_scan_and_save("http://testphp.vulnweb.com", scan)