
from typing import List, Optional

from src.core.model import User, Person
from src.persistence import UserDBManager
from src.logic.secrets import Encoder

from src.core.exceptions import ExistingUserError, UserBindingError

class UserManager():

    def __init__(self):
        self.db_manager = UserDBManager()

    def verify_credentials(self, username: str, password: str) -> tuple[bool, Optional[int]]:
        user: User = self.db_manager.get_user_by_username(username)

        if not user:
            return False, None
        
        valid_password = Encoder.verify_password(
            stored_hash=user.password_hash,  # type: ignore
            password=password,
            salt=user.password_salt  # type: ignore
        )
        
        if not valid_password: # type: ignore
            return False, None
        
        user_id = user.id
        self.db_manager.session.expunge(user)  # Desasociar
        return True, user_id  # type: ignore
    
    def sing_in_user(self, username: str, password: str, email: str) -> User:

        existing_user = self.db_manager.get_user_by_username(username)
        if existing_user:
            raise ExistingUserError(username=username)
        
        existing_person = self.db_manager.get_person_by_email(email)
        if not existing_person:
            raise UserBindingError(username=email, email=email)

        salt = Encoder.generate_salt()
        hashed_password = Encoder.hash_password_with_salt(password, salt)
        
        new_user = User(
            username=username,
            password_hash=hashed_password,
            password_salt=salt,
            person_id=existing_person.id
        )
        
        self.db_manager.create_user(new_user)
        self.db_manager.session.expunge(new_user)
        return new_user
    
    def sign_in_person(self, first_name: str, last_name: str, email: str) -> Person:
        
        existing_person = self.db_manager.get_person_by_email(email)
        if existing_person:
            raise ExistingUserError(username=email)
        
        person = Person(
            first_name=first_name,
            last_name=last_name,
            email=email
        )
        self.db_manager.create_person(person)
        return person
    
    def update_user_password(self, user_id: int, new_password: str) -> None:
        user = self.db_manager.get_user_by_id(user_id)
        if not user:
            raise UserBindingError(username=str(user_id), email="unknown")
        
        new_salt = Encoder.generate_salt()
        new_hashed_password = Encoder.hash_password_with_salt(new_password, new_salt)
        
        user.password_salt = new_salt # type: ignore
        user.password_hash = new_hashed_password # type: ignore
        
        self.db_manager.update_user(user)