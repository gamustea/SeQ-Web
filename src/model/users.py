
from datetime import date


class Person():

    def __init__(self, id: int, name: str, surname: str, email: str, date_created: date):
        self.id = id
        self.name = name
        self.surname = surname
        self.email = email
        self.date_created = date_created

    def __str__(self) -> str:
        return f"{self.name} {self.surname} <{self.email}> (Created on: {self.date_created})"


class User():

    def __init__(self, id: int, username: str, person: Person):
        self.id = id
        self.username = username
        self.person = person

    def __str__(self) -> str:
        return f"{self.username}: {self.person}"