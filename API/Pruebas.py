from API.src.persistence import NmapDBManager
from API.src.misc.documents import PDFCreator, NmapPrintingStrategy

PDFCreator(NmapPrintingStrategy()).print_pdf(NmapDBManager().get_scan_by_id(29))