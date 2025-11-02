
import json
import threading
import time

from src.scanning.tasks import NmapScanTask, NiktoScanTask
from src.misc.configread import ConfigReader
from src.misc.conversion import JSONManager
from src.scanning.scanmanaging import NmapScanManager

from src.persistence.dbmanaging import *
from src.model import *


if __name__ == "__main__":
    user_db_manager = UserDBManager()
    user = user_db_manager.get_user_by_id(1)
    nmap_manager = NmapScanManager(user)
    nmap_manager._do_scan_and_save(
        target_host="127.0.0.1",
        target_ports="22,80,443"
    )

    pass