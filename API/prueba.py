# prueba.py
import requests
import urllib3
import xml.etree.ElementTree as ET
urllib3.disable_warnings()

BASE = "https://192.168.1.143"
s = requests.Session()
s.verify = False

login = s.post(f"{BASE}/gmp", data={
    "cmd": "login",
    "login": "SecOps",
    "password": "djn38qudOdu89ADUSAHDd9831ydhg219hde19"
})

root = ET.fromstring(login.text)
token = root.findtext(".//token")
print(f"Status: {login.status_code}")
print(f"Token: {token}")

if token:
    resp = s.post(f"{BASE}/gmp", data={
        "cmd": "get_tasks",
        "token": token
    })
    print(f"\nget_tasks status: {resp.status_code}")
    print(f"get_tasks body: {resp.text[:300]}")