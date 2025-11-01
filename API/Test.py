
from tests.testreader import TestReader
from tests.testdb import TestUserDBManagerORM

if __name__ == "__main__":
    testDBManager = TestUserDBManagerORM()
    testDBManager.setUp()
    testDBManager.test_people()
    testDBManager.tearDown()

    testDBManager.setUp()
    testDBManager.test_users()
    testDBManager.tearDown()