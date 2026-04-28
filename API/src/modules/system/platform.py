import json
import os
import logging
import platform
import shutil

from pathlib import Path
from enum import Enum

from typing import List,Optional
from pathlib import Path


class PlatformType(Enum):
    """Enumeración de tipos de plataforma"""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class PlatformDetector:
    """
    Detecta la plataforma actual y proporciona utilidades
    para construir comandos adaptados al sistema operativo.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._platform = cls._detect_platform()
            cls._instance._wsl_available = cls._check_wsl()
        return cls._instance

    @staticmethod
    def _detect_platform() -> PlatformType:
        system = platform.system().lower()
        if system == "windows":
            return PlatformType.WINDOWS
        elif system == "linux":
            return PlatformType.LINUX
        elif system == "darwin":
            return PlatformType.MACOS
        return PlatformType.UNKNOWN

    @staticmethod
    def _check_wsl() -> bool:
        if platform.system().lower() != "windows":
            return False
        return shutil.which("wsl") is not None

    @property
    def platform(self) -> PlatformType:
        return self._platform

    @property
    def is_windows(self) -> bool:
        return self._platform == PlatformType.WINDOWS

    @property
    def is_linux(self) -> bool:
        return self._platform == PlatformType.LINUX

    @property
    def is_macos(self) -> bool:
        return self._platform == PlatformType.MACOS

    @property
    def wsl_available(self) -> bool:
        return self._instance._wsl_available if hasattr(self, '_instance') else self._wsl_available

    def wrap_wsl_command(self, cmd: List[str], wsl_distro: str = "Ubuntu", wsl_user: str = "gmiga") -> List[str]:
        """
        Envuelve un comando Linux para ejecutarlo a través de WSL en Windows.
        """
        if not self.is_windows or not self._wsl_available:
            return cmd
        return ["wsl", "-d", wsl_distro, "-u", wsl_user] + cmd

    def convert_path_to_wsl(self, windows_path: str) -> str:
        """
        Convierte una ruta de Windows a formato WSL (/mnt/c/...).
        """
        if not self.is_windows:
            return windows_path
        path = windows_path.replace("\\", "/")
        if len(path) > 2 and path[1] == ":":
            drive = path[0].lower()
            return f"/mnt/{drive}/{path[3:]}"
        return path