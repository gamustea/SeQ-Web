
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
    id = manager.run_task("127.0.0.1", "1-65000", timeout=60)
    print(f"El id del proceso es {id}")

    time.sleep(1)
    if id is not None:
        progress = manager.get_running_task_progress(id) #type: ignore
        while (progress < 99): #type: ignore
            print(f"Progeso: {progress}")
            progress = manager.get_running_task_progress(id) #type: ignore
            time.sleep(0.1)
