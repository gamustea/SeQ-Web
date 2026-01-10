import logging

from src.misc.configread import ConfigReader, DirectoryType
from pathlib import Path


class SecOpsLogger:

    def __init__(self, name=None, level=logging.DEBUG):
        """
        Inicializa un logger con nombre, nivel y archivo de log opcional.
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        reader = ConfigReader()

        if not self.logger.hasHandlers():
            formatter = logging.Formatter(
                "[+] [%(levelname)s] (%(asctime)s) %(message)s"
            )

            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

            path = Path(reader.get_directory_of(DirectoryType.LOG)).resolve()
            path.mkdir(parents=True, exist_ok=True)
            log_file = path / "secops.log"

            if log_file:
                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)

    def get_logger(self):
        """
        Devuelve el logger configurado.
        """
        return self.logger
