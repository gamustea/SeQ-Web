
from src.logic.managers import UserManager, NmapScanManager
from src.logic.documents import PDFCreator, NmapPrintingStrategy

user_manager = UserManager()
user = user_manager.get_user_by_id(1)
scan_manager = NmapScanManager(user)
scan = scan_manager.get_scan_by_id(1)

pdf_creator = PDFCreator(
    printing_strategy=NmapPrintingStrategy(scan)
)