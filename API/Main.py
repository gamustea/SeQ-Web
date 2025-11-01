
import json

from src.scanning.tasks import NmapScanTask, NiktoScanTask
from src.misc.configread import ConfigReader
from src.persistence.dbmanaging import DBManager
from src.model import Person
import threading

import time

if __name__ == "__main__":
    task = NmapScanTask(target_host="192.168.1.1", target_ports="1-1024")

    # Crear hilo para ejecutar el scan asincrónicamente
    scan_thread = threading.Thread(target=task.scan)
    scan_thread.start()
    while (task.progress < 100):
        print(f"Progreso del escaneo: {task.progress }%")
        time.sleep(2)

    # Esperar a que el escaneo termine si no ha terminado ya
    scan_thread.join()
    task.wait()
    print(f"Progress: {task.progress}%")

    print("Resultado del escaneo:")
    print(task.results)