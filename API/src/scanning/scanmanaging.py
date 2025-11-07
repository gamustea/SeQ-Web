
import threading

from typing import Dict, Optional

from src.persistence.dbmanaging import ScanDBManager, NmapDBManager
from src.scanning.tasks import NmapScanTask
from src.model import NmapScan, User
from src.misc.conversion import JSONManager


class NmapScanManager:
    dbmanager: NmapDBManager
    running_tasks: Dict[int, NmapScanTask]
    active_user: User

    def __init__(self, user: User):
        self.dbmanager = NmapDBManager()
        self.running_tasks = {}
        self.active_user = user

    def _do_scan_and_save(
        self, 
        target_host: str,
        target_ports: str,
        nmap_scan_model: NmapScan
    ) -> None:

        task = NmapScanTask(target_host, target_ports)
        task.scan()

        self.running_tasks[nmap_scan_model.id] = task # type: ignore
        task.wait()

        results = JSONManager.convert_json_to_individual_data(task.results, nmap_scan_model) # type: ignore
        nmap_scan_model.results = results

        self.dbmanager.create_nmap_scan(nmap_scan_model)
        for port in results["ports"]:
            port_model = self.dbmanager.get_or_create_port(port[0])
            self.dbmanager.add_target_port(nmap_scan_model, port_model)
            self.dbmanager.add_open_port(nmap_scan_model, port_model, port[2])

    def run_task(
        self,
        target_host: str,
        target_ports: str
    ) -> int:
        nmap_scan_model = NmapScan(
            target=target_host,
            user=self.active_user
        )

        thread = threading.Thread(
            target=self._do_scan_and_save,
            args=(target_host, target_ports, nmap_scan_model)
        )
        thread.start()

        return self.dbmanager.get

    def get_running_task_progress(self, scan_id: int) -> Optional[int]:
        if scan_id in self.running_tasks:
            return self.running_tasks[scan_id].progress
        return None