
import json

from src.scanning.tasks import NmapScanTask, NiktoScanTask
from src.misc.configread import ConfigReader
from src.persistence.dbmanaging import DBManager


if __name__ == "__main__":
    task = NmapScanTask()
    task.scan()

    task = NiktoScanTask()
    task.scan()