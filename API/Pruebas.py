from API.src.persistence import NmapDBManager
from API.src.misc.documents import PDFCreator, NmapPrintingStrategy

PDFCreator(NmapPrintingStrategy(NmapDBManager().get_scan_by_id(1))).print_pdf()