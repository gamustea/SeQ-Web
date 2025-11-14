
import threading

from typing import Dict, Optional, List

from abc import abstractmethod, ABC

from src.persistence.dbmanaging import ScanDBManager, NmapDBManager, DBManager, NiktoDBManager
from src.scanning.tasks import NmapScanTask, NiktoScanTask, _Task
from src.model import NmapScan, User, NiktoScan, NiktoIncident
from src.misc.conversion import JSONManager


class _ScanManager(ABC):
    running_tasks: Dict[int, _Task]
    active_user: User

    def __init__(self, user: User):
        self.running_tasks = {}
        self.active_user = user
        self.thread = None

    def get_running_task_progress(self, id: int) -> Optional[int]:
        if id in self.running_tasks:
            return self.running_tasks[id].progress
        return None
    
    @abstractmethod
    def get_scans_for_user(self) -> List:
        pass


class NmapScanManager(_ScanManager):
    def __init__(self, user: User):
        super().__init__(user)
        self.dbmanager = NmapDBManager()

    def _do_scan_and_save(
        self, 
        target_host: str,
        target_ports: str,
        nmap_scan_model: NmapScan,
        timeout: int = 20
    ) -> None:

        task = NmapScanTask(target_host, target_ports, timeout=timeout)
        self.running_tasks[nmap_scan_model.id] = task   #type: ignore
        
        task.scan()       
        task.wait()

        results = JSONManager.convert_json_to_individual_nmap_data(task.results, nmap_scan_model) # type: ignore
        nmap_scan_model.results = results

        
        for port in results["ports"]:
            port_model = self.dbmanager.get_or_create_port(port[0])
            self.dbmanager.add_target_port(nmap_scan_model, port_model)
            self.dbmanager.add_open_port(nmap_scan_model, port_model, port[2])

    def run_task(
        self,
        target_host: str,
        target_ports: str,
        timeout: int = 20
    ):
        if target_host in self.running_tasks:
            raise Exception(f"A scan is already running for target {target_host}")

        nmap_scan_model = NmapScan(
            target=target_host,
            user=self.active_user
        )
        self.dbmanager.create_nmap_scan(nmap_scan_model)
        self.thread = threading.Thread(
            target=self._do_scan_and_save,
            args=(target_host, target_ports, nmap_scan_model)
        )
        self.thread.start()

        return nmap_scan_model.id

    def get_scans_for_user(self) -> List:
        return self.dbmanager.get_nmap_scans_by_user(self.active_user.id)


class NiktoScanManager(_ScanManager):
    def __init__(self, user: User):
        super().__init__(user)
        self.dbmanager = NiktoDBManager()

    def _do_scan_and_save(self, target_domain: str, nikto_scan_model: NiktoScan, timeout = 20) -> None:
        task = NiktoScanTask(target_domain, timeout)
        self.running_tasks[nikto_scan_model.id] = task  #type: ignore

        task.scan()
        task.wait()

        results = JSONManager.convert_json_to_individual_nikto_data(task.results[-1]) # type: ignore
        task.results = results
        
        for result in results:
            description = result["description"]
            osvdbid = result["osvdbid"]
            method = result["method"]
            description = result["description"]
            uri = result["uri"]

            incident = NiktoIncident()
            incident.description = description
            incident.osvdb_id = osvdbid
            incident.method = method
            incident.url = uri

            new_incident = self.dbmanager.get_or_create_nikto_incident(incident)
            self.dbmanager.add_incident(nikto_scan_model, new_incident)

    def run_task(
        self,
        target_host: str,
        timeout: int = 60
    ):
        if target_host in self.running_tasks:
            raise Exception(f"A scan is already running for target {target_host}")

        nikto_scan_model = NiktoScan(
            target=target_host,
            user=self.active_user
        )

        self.dbmanager.create_nikto_scan(nikto_scan_model)
        self.thread = threading.Thread(
            target=self._do_scan_and_save,
            args=(target_host, nikto_scan_model)
        )
        self.thread.start()

        return nikto_scan_model.id
    
    def get_scans_for_user(self) -> List:
        return self.dbmanager.get_nikto_scans_by_user(self.active_user.id)

