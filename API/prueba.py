from src.core.model import OpenVASScan
from src.logic.managers import UserManager, OpenVASScanManager
from src.misc.conversion import JSONManager
from src.logic.documents import PDFCreator, OpenVASPrintingStrategy

from datetime import datetime

from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform

user = UserManager().get_user_by_id(1)

manager = OpenVASScanManager(user)

scan = manager.get_scan_by_id(1)

pdf_creator = PDFCreator(OpenVASPrintingStrategy(scan))
pdf_creator.print_pdf()

# manager._save_scan_results(scan)
# manager.run_scan("127.0.0.1")
