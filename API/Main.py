
import json
import threading
import time
import os

from src.scanning.tasks import NmapScanTask, NiktoScanTask
from src.misc.configread import ConfigReader
from src.misc.conversion import JSONManager
from src.scanning.scanmanaging import NmapScanManager, NiktoScanManager

from src.persistence.dbmanaging import *
from src.model import *


if __name__ == "__main__":
    user_db_manager = UserDBManager()
    user: User = user_db_manager.get_user_by_id(1)

    manager = NmapScanManager(user)
    manager.run_task("127.0.0.1", "1-65000")
    print("Se pueden hacer cosas mientras se ejecuta el NMAP")
    while True:
        time.sleep(0.5)
        print("Sigue funcionando")