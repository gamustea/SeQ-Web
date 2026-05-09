

import subprocess
import threading
import re
import time

from urllib.parse import urlparse
from pathlib import Path
from typing import Optional, Any, List
from enum import Enum
from abc import ABC, abstractmethod

from lxml import etree as lxml_etree
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.protocols.gmp.requests.v226 import AliveTest

import src.modules.system.config_reading as CR
from src.modules.system import PlatformDetector, SecOpsLogger


class TaskStatus(Enum):
    """
    Enum que representa los diferentes estados en los que puede estar una tarea de escaneo.
    """
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"

    def __str__(self):
        return self.value


class _Task(ABC):
    """
    Clase base abstracta para representar una tarea de escaneo.
    """
    logger = SecOpsLogger(name=__name__).get_logger()

    def __init__(self, target: str, timeout: int = 200000):
        self.timeout = timeout
        self.status: TaskStatus = TaskStatus.PENDING
        self.progress: int = 0
        self.results: Optional[Any] = None
        self.target: str = target
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._finished = threading.Event()
        self._started = threading.Event()
        self._cancel_event = threading.Event()
        self._output_file: Optional[Path] = None

    @abstractmethod
    def _build_command(self) -> List[str]:
        """Construye el comando a ejecutar."""

    def _process_results(self) -> None:
        """Procesa los resultados del escaneo. Override en subclases si es necesario."""

    def _parse_progress(self, line: str) -> int:
        """Extrae el porcentaje de progreso de una línea de salida."""
        match = re.search(r'(\d+(?:\.\d+)?)%', line)
        if match:
            prog_float = float(match.group(1))
            if 0 <= prog_float <= 100:
                return int(round(prog_float))
        return -1

    def _read_output(self):
        """Lee la salida del proceso en un thread separado."""
        try:
            self._started.set()
            while True:
                if self._proc is None or self._proc.stdout is None:
                    break
                line = self._proc.stdout.readline()
                if not line:
                    break
                self.logger.debug(f"Output: {line.strip()}")

                if "Unknown option:" in line or "requires a value" in line:
                    self.logger.error(f"Nikto rechazó el comando (opción inválida): {line.strip()}")
                    self.status = TaskStatus.FAILED

                prog = self._parse_progress(line)
                if prog != -1:
                    with self._lock:
                        self.progress = prog

        except (OSError, IOError) as e:
            self.logger.error(f"Error leyendo salida: {e}")

        finally:
            if self._proc:
                try:
                    self._proc.wait(timeout=10)
                    self.logger.debug(f"Proceso terminó con código: {self._proc.returncode}")
                except subprocess.TimeoutExpired:
                    self.logger.error("Timeout esperando fin del proceso")
                    self._proc.kill()
                    self._proc.wait()

            time.sleep(0.5)
            self._finished.set()

    def scan(self) -> None:
        """Inicia el escaneo de forma ASÍNCRONA."""
        if self._proc and self._proc.poll() is None:
            self.logger.warning("El escaneo ya está en ejecución")
            return

        try:
            self.status = TaskStatus.RUNNING
            cmd = self._build_command()
            self.logger.info(f"Iniciando escaneo con comando: {' '.join(cmd)}")

            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            time.sleep(0.1)
            returncode = self._proc.poll()

            if returncode is not None and returncode != 0:
                self.status = TaskStatus.FAILED
                raise RuntimeError(f"Proceso falló al iniciar (código {returncode})")

            if returncode == 0:
                self.logger.warning("Proceso terminó inmediatamente con código 0.")

            self._thread = threading.Thread(target=self._read_output, daemon=True)
            self._thread.start()

            if not self._started.wait(timeout=5):
                raise RuntimeError("Thread de lectura no inició")

        except (OSError, IOError, RuntimeError) as e:
            self.status = TaskStatus.FAILED
            self.logger.error(f"Error iniciando escaneo: {e}")
            raise

    def wait(self, timeout: Optional[float] = None) -> bool:
        """Espera a que termine el escaneo. Llamada BLOQUEANTE para el thread worker."""
        try:
            if not self._started.is_set():
                self.logger.error("wait() llamado pero scan() nunca se ejecutó")
                return False

            finished = self._finished.wait(timeout)
            if not finished:
                self.status = TaskStatus.TIMEOUT
                self.logger.error("Timeout agotado")
                if self._proc and self._proc.poll() is None:
                    self._proc.kill()
                    self._proc.wait()
                return False

            if self.status in (TaskStatus.CANCELLED, TaskStatus.TIMEOUT, TaskStatus.FAILED):
                self.logger.info(f"wait() termina con estado {self.status.value}")
                return False

            if self._proc and self._proc.returncode != 0:
                self.status = TaskStatus.FAILED
                self.logger.error(f"Proceso terminó con error: código {self._proc.returncode}")
                return False

            self._process_results()

            if self.results is None:
                self.status = TaskStatus.FAILED
                self.logger.error("No se pudieron procesar los resultados")
                return False

            self.status = TaskStatus.COMPLETED
            self.progress = 100
            self.logger.info("Escaneo completado correctamente")
            return True

        except (OSError, IOError, ValueError) as e:
            self.status = TaskStatus.FAILED
            self.logger.error(f"Error en wait: {e}", exc_info=True)
            return False

    def cancel(self) -> None:
        """Cancela el escaneo."""
        self._cancel_event.set()

        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.logger.warning("terminate() no fue suficiente, haciendo kill()")
                self._proc.kill()
                self._proc.wait()

        self.status = TaskStatus.CANCELLED
        self._finished.set()
        self.logger.info("Escaneo cancelado")


class NmapScanTask(_Task):
    """Implementación concreta para escaneos Nmap."""

    def __init__(self, target_host="127.0.0.1", target_ports="1-6000", timeout: int = 300):
        super().__init__(target_host, timeout)
        temp_dir = CR.get_directory_of(CR.DirectoryType.TEMP)

        timestamp = int(time.time() * 1000)
        safe_target = target_host.replace("/", "_").replace(":", "_")
        file_name = f"nmap_scan_{safe_target}_{timestamp}.xml"

        self.target_ports = target_ports
        self._output_file = Path(f"{temp_dir}/{file_name}")
        self.platform = PlatformDetector()

        self._output_file.parent.mkdir(parents=True, exist_ok=True)

    def _build_command(self) -> List[str]:
        nmap_cmd = [
            "sudo", "-n", "nmap",
            "-sV", "-sT",
            "-p", self.target_ports,
            "-oX", str(self._output_file),
            self.target,
            "--stats-every", "1s"
        ]

        if self.platform.is_windows and self.platform.wsl_available:
            wsl_output = self.platform.convert_path_to_wsl(str(self._output_file))
            nmap_cmd = [
                "sudo", "-n", "nmap",
                "-sV", "-sT",
                "-p", self.target_ports,
                "-oX", wsl_output,
                self.target,
                "--stats-every", "1s"
            ]
            return self.platform.wrap_wsl_command(nmap_cmd)

        return nmap_cmd

    def _process_results(self) -> None:
        try:
            output_file = self._output_file

            if not output_file.exists():
                self.logger.error(f"Archivo XML no existe: {output_file}")
                self.results = None
                return

            with output_file.open("r", encoding="utf-8") as f:
                xml_data = f.read()

            if not xml_data.strip():
                self.logger.error("Contenido del XML está vacío")
                self.results = None
                return

            self.results = xml_data
            self.logger.info(f"Resultados procesados: {output_file}")

        except (OSError, IOError) as e:
            self.logger.error(f"Error procesando resultados: {e}", exc_info=True)
            self.results = None
            raise


class NiktoScanTask(_Task):
    """Implementación concreta para escaneos Nikto."""

    def __init__(self, target_domain, timeout: int = 120):
        super().__init__(target_domain, timeout)

        timestamp = int(time.time() * 1000)
        self.temp_path = (
            CR.verify_directory(directory=CR.DirectoryType.TEMP)
            /
            f"nikto_scan_{timestamp}.xml"
        )
        self._output_file = self.temp_path
        self.platform = PlatformDetector()

    def _build_command(self) -> List[str]:
        target = self.target

        raw = target if "://" in target else f"http://{target}"
        parsed = urlparse(raw)

        host = parsed.hostname or target
        use_ssl = parsed.scheme.lower() == "https"
        port = parsed.port or (443 if use_ssl else 80)

        use_wsl = self.platform.is_windows and self.platform.wsl_available

        normal_temp_path = str(self.temp_path)
        wsl_temp_path = self.platform.convert_path_to_wsl(normal_temp_path)
        output_path = (
            wsl_temp_path
            if use_wsl
            else normal_temp_path
        )

        nikto_cmd = [
            "nikto", 
            "-h", host,
            "-port", str(port),
            "-output", output_path,
            "-Format", "xml",
            "-Tuning", "1234569b",
            "-timeout", "10",
            "-nointeractive",
        ]

        if use_ssl:
            nikto_cmd.append("-ssl")

        wrapped_command = self.platform.wrap_wsl_command(nikto_cmd)
        return wrapped_command if use_wsl else nikto_cmd

    def _process_results(self) -> None:
        try:
            if not self.temp_path.exists():
                self.logger.error(f"Archivo XML no existe: {self.temp_path}")
                self.results = None
                return
            if self.temp_path.stat().st_size == 0:
                self.logger.error(f"Archivo XML está vacío: {self.temp_path}")
                self.results = None
                return

            self.results = str(self.temp_path)
            self.logger.info("Resultados Nikto procesados")

        except (OSError, IOError) as e:
            self.logger.error(f"Error procesando resultados Nikto: {e}", exc_info=True)
            self.results = None
            raise


class OpenVASTask(_Task):
    """
    Tarea de escaneo OpenVAS mediante la API GMP (no CLI).
    Gestiona su propio ciclo de vida: setup → polling → reporte.
    """

    _KNOWN_SCAN_CONFIGS = {
        'Full and fast':           'daba56c8-73ec-11df-a475-002264764cea',
        'Full and fast ultimate':  '698f691e-7489-11df-9d8c-002264764cea',
        'Full and very deep':      '708f25c4-7489-11df-8094-002264764cea',
        'System Discovery':        'bbca7412-a950-11e3-9109-406186ea4fc5',
    }

    def __init__(
        self,
        target: str,
        hostname: str,
        port: str,
        username: str,
        password: str,
        scan_config: Optional[str] = None,
        port_list_id: Optional[str] = None,
        timeout: int = 14400
    ):
        super().__init__(target, timeout)
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self._preferred_scan_config = scan_config
        self._preferred_port_list = port_list_id

        self.task_id: Optional[str] = None
        self.report_id: Optional[str] = None

    def _build_command(self) -> List[str]:
        """OpenVAS no usa CLI."""
        return []

    def scan(self) -> None:
        """Inicia el escaneo OpenVAS de forma asíncrona."""
        try:
            self.status = TaskStatus.RUNNING
            self._started.set()
            self._thread = threading.Thread(target=self._execute_openvas_scan, daemon=True)
            self._thread.start()
            self.logger.info(f"Escaneo OpenVAS iniciado para {self.target}")
        except (OSError, RuntimeError) as e:
            self.status = TaskStatus.FAILED
            self.logger.error(f"Error iniciando escaneo OpenVAS: {e}")
            raise

    def wait(self, timeout: Optional[float] = None) -> bool:
        """Override: OpenVAS gestiona su propio ciclo interno."""
        try:
            safe_timeout = min(timeout, 28800) if timeout is not None else None
            #Bloque el hilo hasta que acaba la ejecucuión del Task, falla o acaba el timeout
            finished = self._finished.wait(safe_timeout)

            if not finished:
                self.status = TaskStatus.TIMEOUT
                self.logger.error("Timeout esperando finalización de OpenVAS")
                return False

            if self.status in (TaskStatus.CANCELLED, TaskStatus.FAILED):
                return False

            if self.results is None:
                self.status = TaskStatus.FAILED
                self.logger.error("OpenVAS finalizó pero no hay resultados")
                return False

            self.status = TaskStatus.COMPLETED
            self.progress = 100
            return True

        except (OSError, IOError, ValueError) as e:
            self.status = TaskStatus.FAILED
            self.logger.error(f"Error en wait de OpenVAS: {e}", exc_info=True)
            return False

    def cancel(self) -> None:
        """Cancela el escaneo deteniendo la tarea en OpenVAS."""
        self._cancel_event.set()
        self.status = TaskStatus.CANCELLED
        self.logger.info("Cancelación solicitada; se detendrá en el próximo ciclo de polling")

    def _execute_openvas_scan(self) -> None:
        try:
            with self._create_gmp_connection() as gmp:
                gmp.authenticate(self.username, self.password)
                target_id = self._get_or_create_target(gmp)
                scanner_id = self._get_default_scanner(gmp)
                self._create_and_start_task(gmp, target_id, scanner_id)

            self._wait_for_completion()

            if self.status == TaskStatus.CANCELLED:
                self._finished.set()
                return

            with self._create_gmp_connection() as gmp:
                gmp.authenticate(self.username, self.password)
                self._fetch_report(gmp)

            self._finished.set()

        except (OSError, RuntimeError) as e:
            self.status = TaskStatus.FAILED
            self.logger.error(f"Error en escaneo OpenVAS: {e}", exc_info=True)
            self._finished.set()

    def _create_gmp_connection(self) -> Gmp:
        """Crea una conexión GMP nueva. Usar siempre con 'with'."""
        connection = TLSConnection(
            hostname=self.hostname,
            port=self.port,
            timeout=60
        )
        return Gmp(connection=connection, transform=EtreeTransform())

    def _extract_id_from_response(self, response, entity_name: str) -> Optional[str]:
        """
        Extrae el ID de una respuesta GMP probando múltiples estrategias.
        Evita duplicar esta lógica en cada método.
        """
        entity_id = response.attrib.get('id')
        if entity_id:
            return entity_id

        ids = response.xpath('@id')
        if ids:
            return ids[0]

        id_el = response.find('id')
        if id_el is not None and id_el.text:
            return id_el.text.strip()

        sub_el = response.find(entity_name)
        if sub_el is not None:
            entity_id = sub_el.get('id')
            if entity_id:
                return entity_id

        self.logger.error(
            f"No se pudo extraer ID de respuesta '{entity_name}': "
            f"{lxml_etree.tostring(response, encoding='unicode')}"
        )
        return None

    def _get_or_create_target(self, gmp: Gmp) -> str:
        target_name = f"Target_{self.target}"

        targets = gmp.get_targets(filter_string=f'name="{target_name}"')
        target_list = targets.xpath('target')
        if target_list:
            target_id = target_list[0].attrib.get('id')
            self.logger.info(f"Reutilizando target existente: {target_id}")
            return target_id

        port_list_id = self._preferred_port_list or self._get_or_create_port_list(gmp)

        self.logger.info(f"Creando target para {self.target}")
        target_response = gmp.create_target(
            name=target_name,
            hosts=[self.target],
            port_list_id=port_list_id,
            comment=f"Target para {self.target}",
            alive_test=AliveTest.CONSIDER_ALIVE
        )

        target_id = self._extract_id_from_response(target_response, 'target')
        if not target_id:
            raise RuntimeError("No se pudo obtener el target_id de la respuesta")

        self.logger.info(f"Target creado: {target_id}")
        return target_id

    def _get_default_scanner(self, gmp: Gmp) -> str:
        """Obtiene el scanner OpenVAS por defecto."""
        scanners = gmp.get_scanners()
        for scanner in scanners.xpath('scanner'):
            name_el = scanner.find('name')
            if name_el is not None and name_el.text == 'OpenVAS Default':
                scanner_id = scanner.get('id')
                self.logger.info(f"Scanner encontrado: {scanner_id}")
                return scanner_id

        raise RuntimeError("No se encontró el scanner 'OpenVAS Default'")

    def _get_or_create_port_list(self, gmp: Gmp) -> str:
        """Obtiene o crea una port list."""
        port_lists = gmp.get_port_lists()
        preferred_names = {'All IANA assigned TCP', 'Default', 'OpenVAS Default'}

        for port_list in port_lists.xpath('port_list'):
            name_el = port_list.find('name')
            if name_el is not None and name_el.text in preferred_names:
                port_list_id = port_list.get('id')
                self.logger.info(f"Port list encontrado: {name_el.text} ({port_list_id})")
                return port_list_id

        # Usar el primero disponible si no hay uno preferido
        first = port_lists.xpath('port_list')
        if first:
            port_list_id = first[0].get('id')
            name = first[0].findtext('name', 'desconocido')
            self.logger.info(f"Usando primer port_list disponible: {name} ({port_list_id})")
            return port_list_id

        # Crear uno básico si no existe ninguno
        self.logger.info("Creando port_list predeterminado")
        response = gmp.create_port_list(
            name="SeQ Default",
            port_range="T:1-1024,U:1-1024",
            comment="Port list creado automáticamente por SeQ"
        )
        port_list_id = self._extract_id_from_response(response, 'port_list')
        if not port_list_id:
            raise RuntimeError("No se pudo crear ni obtener un port_list")

        self.logger.info(f"Port list creado: {port_list_id}")
        return port_list_id

    def _get_default_scan_config(self, gmp: Gmp) -> str:
        """
        Obtiene el scan_config a usar.
        Prioridad: 1) preferencia explícita, 2) buscar en servidor,
        3) fallback a UUID conocido de 'Full and fast'.
        """
        if self._preferred_scan_config:
            self.logger.info(f"Usando scan_config explícito: {self._preferred_scan_config}")
            return self._preferred_scan_config

        scan_configs = gmp.get_scan_configs()
        configs = scan_configs.xpath('config')

        if not configs:
            # Los feeds aún no están cargados. Usar UUID conocido como fallback.
            fallback_id = self._KNOWN_SCAN_CONFIGS['Full and fast']
            self.logger.warning(
                f"No hay scan_configs en el servidor. "
                f"Usando UUID de fallback 'Full and fast': {fallback_id}. "
                f"Asegúrate de que los feeds de Greenbone estén sincronizados."
            )
            return fallback_id

        # Buscar preferencias en orden
        preferred = ['Full and fast', 'Full and fast ultimate', 'System Discovery']
        config_map = {}
        for config in configs:
            name_el = config.find('name')
            if name_el is not None and name_el.text:
                config_map[name_el.text] = config.get('id')
                self.logger.info(f"Scan config disponible: {name_el.text} ({config.get('id')})")

        for pref in preferred:
            if pref in config_map:
                self.logger.info(f"Usando scan_config: {pref}")
                return config_map[pref]

        # Usar el primero disponible
        first_id = configs[0].get('id')
        self.logger.info(f"Usando primer scan_config disponible: {first_id}")
        return first_id

    def _create_and_start_task(self, gmp: Gmp, target_id: str, scanner_id: str) -> None:
        scan_config_id = self._get_default_scan_config(gmp)
        task_name = f"SeQ_Scan_{self.target}_{int(time.time())}"

        task_response = gmp.create_task(
            name=task_name,
            config_id=scan_config_id,
            target_id=target_id,
            scanner_id=scanner_id,
            comment=f"Escaneo de {self.target} iniciado por SeQ"
        )

        self.task_id = self._extract_id_from_response(task_response, 'task')
        if not self.task_id:
            raise RuntimeError("No se pudo obtener el task_id de la respuesta de create_task")

        self.logger.info(f"Tarea creada: {self.task_id}")

        start_response = gmp.start_task(self.task_id)
        report_ids = start_response.xpath('report_id')
        if not report_ids or not report_ids[0].text:
            raise RuntimeError("No se pudo obtener el report_id al iniciar la tarea")

        self.report_id = report_ids[0].text
        self.logger.info(f"Escaneo iniciado. Report ID: {self.report_id}")

    def _wait_for_completion(self, check_interval: int = 60) -> None:
        """Espera a que el escaneo complete reconectando en cada iteración."""
        while True:
            if self._cancel_event.is_set():
                try:
                    with self._create_gmp_connection() as gmp:
                        gmp.authenticate(self.username, self.password)
                        gmp.stop_task(self.task_id)
                        self.logger.info(f"Tarea {self.task_id} detenida en OpenVAS")
                except (OSError, RuntimeError) as e:
                    self.logger.error(f"Error deteniendo tarea: {e}")
                self.status = TaskStatus.CANCELLED
                break

            try:
                with self._create_gmp_connection() as gmp:
                    gmp.authenticate(self.username, self.password)
                    task = gmp.get_task(self.task_id)
            except (OSError, RuntimeError) as e:
                self.logger.warning(
                    f"Error consultando tarea, reintentando en {check_interval}s: {e}"
                )
                time.sleep(check_interval)
                continue

            status_els = task.xpath('task/status')
            progress_els = task.xpath('task/progress')

            if not status_els:
                self.logger.warning("Respuesta de tarea sin campo 'status', reintentando...")
                time.sleep(check_interval)
                continue

            status = status_els[0].text
            progress_text = progress_els[0].text if progress_els else "0"

            try:
                with self._lock:
                    self.progress = max(0, int(float(progress_text)))
            except (ValueError, TypeError):
                pass

            self.logger.info(f"Estado: {status} | Progreso: {progress_text}%")

            if status == 'Done':
                break
            elif status in ('Stopped', 'Interrupted'):
                self.logger.warning(f"Escaneo terminó con estado: {status}")
                self.status = TaskStatus.CANCELLED
                break

            time.sleep(check_interval)

    # ── Reporte y parseo ──────────────────────────────────────────────────────

    def _fetch_report(self, gmp: Gmp) -> None:
        """Obtiene el reporte XML del escaneo."""
        report_response = gmp.get_report(
            report_id=self.report_id,
            report_format_id='a994b278-1f62-11e1-96ac-406186ea4fc5',
            ignore_pagination=True,
            details=True
        )
        self.results = lxml_etree.tostring(report_response, encoding='unicode', pretty_print=True)
        self.logger.info("Reporte XML obtenido")
