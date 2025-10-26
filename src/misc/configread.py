import json
from pathlib import Path
from typing import Optional


class ConfigReader:

    def __init__(self, configs_file: str = "src/config/SecConfig.json") -> None:
        self.configs_path = Path(configs_file).resolve()

    def read_configs(self) -> dict:
        with open(self.configs_path, "r") as config_file:
            configs = json.load(config_file)

        return configs

    def get_db_crendetials(self) -> tuple:
        configs = self.read_configs()
        usermane = configs["dbconfig"]["username"]
        password = configs["dbconfig"]["password"]
        host = configs["dbconfig"]["host"]
        database = configs["dbconfig"]["dbname"]

        return (usermane, password, host, database)
