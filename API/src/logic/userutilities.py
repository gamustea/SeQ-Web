
from typing import List, Optional

from src.core.model import User
from src.persistence import UserDBManager

class UserManager():

    def __init__(self):
        self.db_manager = UserDBManager()

    def verify_credentials(self, username: str, password: str) -> tuple[bool, Optional[int]]:
        user: User = self.db_manager.get_user_by_username(username)
        
        if not user or user.password != password: #type: ignore
            return False, None
        
        user_id = user.id
        self.db_manager.session.expunge(user)  # Desasociar
        return True, user_id  # type: ignore