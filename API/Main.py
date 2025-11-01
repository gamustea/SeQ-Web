
import json

from src.scanning.tasks import NmapScanTask, NiktoScanTask
from src.misc.configread import ConfigReader
from src.persistence.dbmanaging import DBManager
from API.src.model import Person

if __name__ == "__main__":
    task = NiktoScanTask()
    task.scan()
    print(task.get_task_results())
    pass