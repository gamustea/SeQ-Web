
from typing import List, Optional

from src.core.model import User, Person
from src.persistence import UserDBManager
from src.logic.secrets import Encoder

from src.core.exceptions import ExistingUserError, UserBindingError

class UserManager():

    def __init__(self):
        self.db_manager = UserDBManager()

    