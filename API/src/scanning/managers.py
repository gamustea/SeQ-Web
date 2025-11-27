import threading

from datetime import datetime
from typing import Dict, Optional, List
from abc import abstractmethod, ABC

from src.persistence import (
    ScanDBManager,
    NmapDBManager,
    DBManager,
    NiktoDBManager,
)

from src.scanning.tasks import NmapScanTask, NiktoScanTask, _Task
from src.model import NmapScan, User, NiktoScan, NiktoIncident, Scan
from src.misc.conversion import JSONManager
from src.misc.logging import SecOpsLogger

# Configurar logger
logger_instance = SecOpsLogger(name="ScanManager")
logger = logger_instance.get_logger()


def assign_severity_to_nikto_incident(incident):
    """Tu función existente - mantenla igual"""
    # [... mantén toda tu lógica existente ...]
    pass  # Placeholder para brevedad


class _ScanManager(ABC):
    def __init__(self, user: User):
        self.running_tasks = {}
        self.active_user = user
        self.thread = None
        self.dbmanager: ScanDBManager = None  # type: ignore
        
    def cleanup(self):
        """Cierra la sesión del dbmanager"""
        if self.dbmanager and hasattr(self.dbmanager, 'session'):
            try:
                self.dbmanager.session.close()
            except:
                pass

    def get_running_task_progress(self, id: int) -> Optional[int]:
        if id in self.running_tasks:
            progress = self.running_tasks[id].progress
            logger.debug(f"Progreso de tarea {id}: {progress}%")
            return progress
        logger.warning(f"Tarea {id} no encontrada en tareas en ejecución")
        return None

    @abstractmethod
    def get_scans_for_user(self) -> List:
        pass

    def scan_is_finished(self, scan: Scan) -> bool:
        """Verifica si un escaneo ha finalizado."""
        try:
            if not self.dbmanager:
                logger.error("dbmanager no está inicializado")
                return False

            return self.dbmanager.scan_is_finished(scan.id)  # type: ignore
        except Exception as e:
            logger.error(
                f"Error al verificar si el escaneo {scan.id} está terminado: {e}"
            )
            return False


class NmapScanManager(_ScanManager):
    """Gestor específico para escaneos Nmap."""

    def __init__(self, user: User):
        super().__init__(user)
        self.dbmanager = NmapDBManager()
        logger.info("NmapScanManager inicializado correctamente")

    def _do_scan_and_save(
        self,
        target_host: str,
        target_ports: str,
        nmap_scan_model: NmapScan,
        timeout: int = 20,
    ) -> None:
        """Ejecuta el escaneo Nmap y guarda los resultados."""
        try:
            logger.info(
                f"Iniciando escaneo Nmap: target={target_host}, ports={target_ports}, timeout={timeout}"
            )

            task = NmapScanTask(target_host, target_ports, timeout=timeout)
            self.running_tasks[nmap_scan_model.id] = task  # type: ignore
            logger.info(f"Ejecutando escaneo Nmap con ID {nmap_scan_model.id}")

            task.scan()
            finished = task.wait()

            if finished:
                logger.info(
                    f"Escaneo Nmap {nmap_scan_model.id} completado, procesando resultados"
                )
                results = JSONManager.convert_json_to_individual_nmap_data(
                    task.results, nmap_scan_model  # type: ignore
                )
                nmap_scan_model.results = results

                # Procesar puertos encontrados
                ports_count = len(results["ports"])
                logger.info(
                    f"Procesando {ports_count} puertos del escaneo {nmap_scan_model.id}"
                )

                for port in results["ports"]:
                    port_model = self.dbmanager.get_or_create_port(port[0])
                    self.dbmanager.add_target_port(nmap_scan_model, port_model)
                    self.dbmanager.add_open_port(nmap_scan_model, port_model, port[2])

                # HACER UN SOLO COMMIT AL FINAL DEL LOOP
                try:
                    self.dbmanager.session.commit()
                    logger.info(
                        f"Escaneo Nmap {nmap_scan_model.id} guardado exitosamente con {ports_count} puertos"
                    )
                except Exception as commit_err:
                    self.dbmanager.session.rollback()
                    logger.error(f"Error al guardar puertos: {commit_err}")
                    raise
                
                logger.info(
                    f"Escaneo Nmap {nmap_scan_model.id} guardado exitosamente con {ports_count} puertos"
                )

                # Marcar como terminado
                self.dbmanager.set_scan_as_finished(nmap_scan_model)
                logger.info(f"Escaneo Nmap {nmap_scan_model.id} marcado como terminado")
            else:
                logger.info(f"El escaneo con id {nmap_scan_model.id} fue cancelado")

        except Exception as e:
            logger.error(
                f"Error en escaneo Nmap {nmap_scan_model.id}: {str(e)}", exc_info=True
            )
            raise

    def run_task(self, target_host: str, target_ports: str, timeout: int = 20):
        """Inicia una tarea de escaneo Nmap en un thread separado."""
        try:
            if target_host in self.running_tasks:
                logger.warning(
                    f"Intento de escaneo duplicado para target: {target_host}"
                )
                raise Exception(f"A scan is already running for target {target_host}")

            logger.info(f"Creando nuevo escaneo Nmap para {target_host}")
            nmap_scan_model = NmapScan(target=target_host, user=self.active_user)
            nmap_scan_model.started_at = datetime.now()  # type: ignore

            self.dbmanager.create_nmap_scan(nmap_scan_model)
            logger.info(f"Escaneo Nmap {nmap_scan_model.id} creado, iniciando thread")

            self.thread = threading.Thread(
                target=self._do_scan_and_save,
                args=(target_host, target_ports, nmap_scan_model),
            )
            self.thread.start()

            logger.info(
                f"Thread de escaneo Nmap {nmap_scan_model.id} iniciado exitosamente"
            )

            return nmap_scan_model.id

        except Exception as e:
            logger.error(f"Error al iniciar tarea Nmap: {str(e)}", exc_info=True)
            raise

    def get_scans_for_user(self) -> List:
        """Obtiene todos los escaneos Nmap del usuario."""
        try:
            logger.info(f"Obteniendo escaneos Nmap para usuario {self.active_user.id}")
            scans = self.dbmanager.get_nmap_scans_by_user(self.active_user.id)
            logger.info(
                f"Se obtuvieron {len(scans)} escaneos Nmap para usuario {self.active_user.id}"
            )
            return scans
        except Exception as e:
            logger.error(
                f"Error al obtener escaneos Nmap para usuario {self.active_user.id}: {str(e)}",
                exc_info=True,
            )
            raise

    def get_scan_by_id(self, id: int) -> Scan:
        """Obtiene un escaneo Nmap específico por ID."""
        try:
            logger.info(f"Obteniendo escaneo Nmap con ID: {id}")
            # CORRECCIÓN: Usar el método específico de NmapDBManager
            scan = self.dbmanager.get_nmap_scan_by_id(int(id))
            if scan:
                logger.info(f"Escaneo Nmap {id} obtenido exitosamente")
            else:
                logger.warning(f"Escaneo Nmap {id} no encontrado")
            return scan
        except Exception as e:
            logger.error(f"Error al obtener escaneo Nmap {id}: {str(e)}", exc_info=True)
            raise


class NiktoScanManager(_ScanManager):
    """Gestor específico para escaneos Nikto."""

    def __init__(self, user: User):
        super().__init__(user)
        self.dbmanager = NiktoDBManager()
        logger.info("NiktoScanManager inicializado correctamente")

    def _do_scan_and_save(
        self, target_domain: str, nikto_scan_model: NiktoScan, timeout=20
    ) -> None:
        """Ejecuta el escaneo Nikto y guarda los resultados."""
        try:
            logger.info(
                f"Iniciando escaneo Nikto: target={target_domain}, timeout={timeout}"
            )

            task = NiktoScanTask(target_domain, timeout)
            self.running_tasks[nikto_scan_model.id] = task  # type: ignore
            logger.info(f"Ejecutando escaneo Nikto con ID {nikto_scan_model.id}")

            task.scan()
            finished = task.wait()

            if finished:
                logger.info(
                    f"Escaneo Nikto {nikto_scan_model.id} completado, procesando resultados"
                )
                results = JSONManager.convert_json_to_individual_nikto_data(
                    task.results[-1]  # type: ignore
                )
                task.results = results

                # Procesar incidentes encontrados
                incidents_count = len(results)
                logger.info(
                    f"Procesando {incidents_count} incidentes del escaneo Nikto {nikto_scan_model.id}"
                )

                for result in results:
                    description = result["description"]
                    osvdbid = result["osvdbid"]
                    method = result["method"]
                    uri = result["uri"]

                    incident = NiktoIncident()
                    incident.description = description
                    incident.osvdb_id = osvdbid
                    incident.method = method
                    incident.url = uri

                    assign_severity_to_nikto_incident(incident)

                    new_incident = self.dbmanager.get_or_create_nikto_incident(incident)  # type: ignore
                    self.dbmanager.add_incident(nikto_scan_model, new_incident)

                logger.info(
                    f"Escaneo Nikto {nikto_scan_model.id} guardado exitosamente con {incidents_count} incidentes"
                )

                # Marcar como terminado
                self.dbmanager.set_scan_as_finished(nikto_scan_model)
                logger.info(
                    f"Escaneo Nikto {nikto_scan_model.id} marcado como terminado"
                )
            else:
                logger.info(f"El escaneo con id {nikto_scan_model.id} se canceló")

        except Exception as e:
            logger.error(
                f"Error en escaneo Nikto {nikto_scan_model.id}: {str(e)}", exc_info=True
            )
            raise

    def run_task(self, target_host: str, timeout: int = 60):
        """Inicia una tarea de escaneo Nikto en un thread separado."""
        try:
            if target_host in self.running_tasks:
                logger.warning(
                    f"Intento de escaneo Nikto duplicado para target: {target_host}"
                )
                raise Exception(f"A scan is already running for target {target_host}")

            logger.info(f"Creando nuevo escaneo Nikto para {target_host}")
            nikto_scan_model = NiktoScan(target=target_host, user=self.active_user)
            nikto_scan_model.started_at = datetime.now()  # type: ignore

            self.dbmanager.create_nikto_scan(nikto_scan_model)
            logger.info(f"Escaneo Nikto {nikto_scan_model.id} creado, iniciando thread")

            self.thread = threading.Thread(
                target=self._do_scan_and_save, args=(target_host, nikto_scan_model)
            )
            self.thread.start()

            logger.info(
                f"Thread de escaneo Nikto {nikto_scan_model.id} iniciado exitosamente"
            )

            return nikto_scan_model.id

        except Exception as e:
            logger.error(f"Error al iniciar tarea Nikto: {str(e)}", exc_info=True)
            raise

    def get_scans_for_user(self) -> List:
        """Obtiene todos los escaneos Nikto del usuario."""
        try:
            logger.info(f"Obteniendo escaneos Nikto para usuario {self.active_user.id}")
            scans = self.dbmanager.get_nikto_scans_by_user(self.active_user.id)
            logger.info(
                f"Se obtuvieron {len(scans)} escaneos Nikto para usuario {self.active_user.id}"
            )
            return scans
        except Exception as e:
            logger.error(
                f"Error al obtener escaneos Nikto para usuario {self.active_user.id}: {str(e)}",
                exc_info=True,
            )
            raise

    def get_scan_by_id(self, id: int) -> Scan:
        """Obtiene un escaneo Nikto específico por ID."""
        try:
            logger.info(f"Obteniendo escaneo Nikto con ID: {id}")
            # CORRECCIÓN: Usar el método específico de NiktoDBManager
            scan = self.dbmanager.get_nikto_scan_by_id(id)
            if scan:
                logger.info(f"Escaneo Nikto {id} obtenido exitosamente")
            else:
                logger.warning(f"Escaneo Nikto {id} no encontrado")
            return scan
        except Exception as e:
            logger.error(
                f"Error al obtener escaneo Nikto {id}: {str(e)}", exc_info=True
            )
            raise
