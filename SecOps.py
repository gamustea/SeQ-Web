
from src.tasks import NmapScanTask, NiktoScanTask


if __name__ == "__main__":
    task = NiktoScanTask()
    task.scan()
    print(task.get_task_results())