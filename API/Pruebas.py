from src.persistence.dbmanaging import NmapDBManager
from src.documents import PDFCreator

PDFCreator().print_nmap_pdf(NmapDBManager().get_scan_by_id(29))