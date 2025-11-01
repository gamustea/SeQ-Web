
from typing import List
from pathlib import Path

from src.misc.configread import ConfigReader


class DirectoryChecker:

    def __init__(self):
        self.config_reader = ConfigReader()

    def verify_directory(self, directory: str) -> Path:
        dir_path = Path(self.config_reader.get_directory_of(directory)).resolve()
        dir_path.mkdir(parents=True, exist_ok=True)

        return dir_path