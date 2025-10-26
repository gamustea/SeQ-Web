
import json

from src.scanning.tasks import NmapScanTask, NiktoScanTask
from src.misc.configread import ConfigReader
from src.persistence.dbmanaging import DBManager



if __name__ == "__main__":
    reader = ConfigReader()
    db_credentials = reader.get_db_crendetials()
    print("Database Credentials:", db_credentials)