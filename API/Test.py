from tests.testreader import TestReader
from tests.testdb import TestUserDBManager, TestScanDBManager

if __name__ == "__main__":

    testDBManager = TestUserDBManager()
    testDBManager.setUp()
    testDBManager.test_people()
    testDBManager.tearDown()

    testDBManager.setUp()
    testDBManager.test_users()
    testDBManager.tearDown()

        
    testDBManager = TestScanDBManager()
    testDBManager.setUp()
    testDBManager.test_create_scan_and_exists()
    testDBManager.test_get_scan_by_id()
    testDBManager.test_update_scan()
    testDBManager.test_delete_scan()
    testDBManager.tearDown()
