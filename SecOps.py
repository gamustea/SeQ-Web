
from src.portscanner import SelfPortScanner


scanner = SelfPortScanner("127.0.0.1")
print(scanner.wide_scan())