from src.core.model import OpenVASScan
from src.logic.managers import UserManager, OpenVASScanManager
from src.misc.conversion import JSONManager
from datetime import datetime
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform

user = UserManager().get_user_by_id(1)
manager = OpenVASScanManager(user)
manager.run_scan("192.168.1.1")
