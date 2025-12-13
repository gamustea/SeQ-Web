
from src.logic.secrets import Encoder
from src.logic.userutilities import UserManager

manager = UserManager()

manager.sign_in_person(
    first_name="Gabriel",
    last_name="Musteata",
    email="gmiganescu@gmail.com"
)

manager.sing_in_user("gmusteata", "06No2004", "gmiganescu@gmail.com")