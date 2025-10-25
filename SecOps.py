
import json

from src.tasks import NmapScanTask, NiktoScanTask



if __name__ == "__main__":
    task = NmapScanTask(target_host="192.168.1.1")
    task.scan()
    with open("archivo.json", "w") as archivo_json:
        json.dump(task.get_task_results(), archivo_json, indent=4)