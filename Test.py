
from tests.testreader import TestReader
from tests.testdb import TestUserDBManager

if __name__ == "__main__":
    testDBManager = TestUserDBManager()
    people = testDBManager.test_get_people()
    person = testDBManager.test_get_person_by_id(2)
    print(f"Persona con ID 2: {person}")
    users = testDBManager.test_get_users()
    for user in users:
        print(user)