
from src.tasks import NmapScanTask

if __name__ == "__main__":
    task = NmapScanTask()
    task.scan()
    print(task.get_task_results())
    pass