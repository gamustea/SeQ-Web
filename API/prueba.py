from src.core.model import OpenVASScan
from src.logic.managers import UserManager, OpenVASScanManager, NiktoScanManager, NmapScanManager
from src.misc.conversion import JSONManager
from src.logic.documents import PDFCreator, OpenVASPrintingStrategy, NiktoPrintingStrategy, NmapPrintingStrategy

from datetime import datetime
from time import sleep

from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform

user = UserManager().get_user_by_id(1)

manager = OpenVASScanManager(user)
# scan_id = manager.run_scan("192.168.1.1")


scan = manager.get_scan_by_id(35)

# while not manager.is_scan_finished(scan_id):
#     sleep(1)
#     print("Esperando a que acabe el escaneo...")

print(f"Escaneo terminado: {manager.is_scan_finished(scan.id)}")
pdfmaker = PDFCreator(OpenVASPrintingStrategy(scan))
pdfmaker.print_pdf()
