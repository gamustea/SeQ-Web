import json
import os
import logging
import platform
import shutil

from pathlib import Path
from enum import Enum

from typing import List, Optional
from pathlib import Path


class SecOpsLogger:

    def __init__(self, name=None, level=logging.DEBUG):
        """
        Inicializa un logger con nombre, nivel y archivo de log opcional.
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        if not self.logger.hasHandlers():
            formatter = logging.Formatter(
                "[+] [%(levelname)s] (%(asctime)s) %(message)s"
            )

            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

            import src.modules.system.config_reading as CR
            path = Path(CR.get_directory_of(CR.DirectoryType.LOG)).resolve()
            path.mkdir(parents=True, exist_ok=True)
            log_file = path / "secops.log"

            if log_file:
                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)

        for _noisy in ("ddgs", "curl_cffi", "httpx", "httpcore", "h2", "hyper"):
            logging.getLogger(_noisy).setLevel(logging.WARNING)

    def get_logger(self):
        """
        Devuelve el logger configurado.
        """
        return self.logger