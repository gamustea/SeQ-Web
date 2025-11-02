
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
        target_ports: str
    ) -> None:

        task = NmapScanTask(target_host, target_ports)
        task.scan()

        nmap_scan_model = NmapScan(
            target=target_host,
            user=self.active_user
        )

        self.running_tasks[nmap_scan_model.id] = task # type: ignore
        task.wait()

        results = JSONManager.convert_json_to_individual_data(task.results, nmap_scan_model) # type: ignore
        nmap_scan_model.results = results

        self.dbmanager.create_nmap_scan(nmap_scan_model)
        for port in results["ports"]:
            port_model = self.dbmanager.get_or_create_port(port[0])
            self.dbmanager.add_target_port(nmap_scan_model, port_model)
            self.dbmanager.add_open_port(nmap_scan_model, port_model, port[2])

