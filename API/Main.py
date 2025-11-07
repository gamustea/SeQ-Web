
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
    user: User = user_db_manager.get_user_by_id(1)
    nmap_manager = NmapScanManager(user)
    id = nmap_manager.run_task(
        target_host="127.0.0.1",
        target_ports="1-65000"
    )
    


    pass