
from tests.testreader import TestReader
from tests.testdb import TestUserDBManager

if __name__ == "__main__":

    testDBManager = TestUserDBManager()
    testDBManager.test_people()