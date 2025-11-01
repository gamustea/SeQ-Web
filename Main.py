
import json

from src.scanning.tasks import NmapScanTask, NiktoScanTask
from src.misc.configread import ConfigReader
from src.persistence.dbmanaging import DBManager
from model.users import Person

if __name__ == "__main__":
    person = Person(
        name="Gabriel",
        surname="Musteata",
        email="gamustea@unirioja.es"
    )