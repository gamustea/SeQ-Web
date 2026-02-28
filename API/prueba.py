
import json
from src.logic.managers import NmapScanManager, UserManager, VaultManager

user_manager = UserManager()
user = user_manager.get_user_by_id(1)

# manager = NmapScanManager(user)
# scan_id = manager.run_scan("127.0.0.1", "1-1024", timeout=300)
# manager.cancel_scan(scan_id)

json_string = """{
  "checker": "5vg6+H9BieFg1sGZLVKTUPD4TvFzncq4c0+NqfgGRKVAz642fHUtmNNrtmVLz/QxdTNWHlke0hTA1fY8ZVJRwqq+tbm/xDpGHb5loyyBBvQ2UUnodkQUKps9Swk=",
  "vaultKey": "NIn/YojYl67V+UyMJQVpS17NS3z0Xk/El/H2U5dLc0eRLQ3fWqKHUiOXZ6hqqHkOEKC2xTuN2mmTBzE8U3Q9EUCWmVL+ELLP",
  "algorithm": {
    "transformation": "AES/GCM/NoPadding",
    "kdf": "Argon2",
    "kdfIterations": "3",
    "kdfMemoryKiB": "65536",
    "kdfParallelism": "1",
    "salt": "ChuqieJ4iA1EC0UcCVCrVw=="
  },
  "accounts": [
    {
      "id": "ACC0",
      "title": "Gmail Account",
      "createdAt": "2026-02-28T16:09:55.567+01:00",
      "updatedAt": "2026-02-28T16:09:55.567+01:00",
      "allowedUsers": [],
      "username": "MDYkhWS3otSQ2fe9wcLXKYK2Sl2qZCyaGqbA1YGXC0g//8PSUGLOQ/CF",
      "domain": "0PmCzSbgYXh7EHiZTqzIwGTZnhsbJ4hT16OEKgeQkAj2gGWFZgJABI2P6g==",
      "password": "6N8gGZsTydWXNV4djgs1qpy+ga4XOUGX722eqmliC8HHpGZX0Hd/Ig=="
    },
    {
      "id": "ACC1",
      "title": "Github Account",
      "createdAt": "2026-02-28T16:09:55.568+01:00",
      "updatedAt": "2026-02-28T16:09:55.568+01:00",
      "allowedUsers": [],
      "username": "A9ai4QVp+Se3YzlEaO+Bd6j4weoqavxFv8/gycLMOOj9AJhk",
      "domain": "zuaTycrtm3d4ZjB0hMPttuRXBhsuVhzkQZPhNeUZeBJI5RgndNc=",
      "password": "8NIWKtkOYw0C9wHFEBQNZhh8CMCdmU6P9W89SyjlHyFy6XBcSZy3XpVMBw=="
    },
    {
      "id": "ACC2",
      "title": "Netflix Account",
      "createdAt": "2026-02-28T16:09:55.568+01:00",
      "updatedAt": "2026-02-28T16:09:55.568+01:00",
      "allowedUsers": [],
      "username": "KsKfKrLCpLlz3jfI89OPkhbLO0InS7McGwrxQFOggN/Bkc4VRFgGt9Or",
      "domain": "t2ZZfLlwp6l5jSc+ov9/ulKzgasKzD3Aka2aoyFnwcpxjI1DzHOu",
      "password": "amiq0eEH1XYzOj0qTVK0FcbzFM+vJtipQgoZovTz9ve+zcpAinuOcA=="
    }
  ],
  "creditcards": [
    {
      "id": "CDC3",
      "title": "Personal Card",
      "createdAt": "2026-02-28T16:09:55.568+01:00",
      "updatedAt": "2026-02-28T16:09:55.568+01:00",
      "allowedUsers": [],
      "cardHolderName": "VIEkTx2hrmd3U5QTczDEytXqckHUAkMTxnmnI842ezCeU0KjMbeo+5Sw8k0=",
      "cardNumber": "lXId+D+obGQ6KvjdeW9IYoI4dNuosNfnSrS+tNZZ5wqISKPMxcqTTolrVHs=",
      "expirationDate": "mStXyySzuUT9sn10OLzhKInDl9Nu3q6ycKCB8qe7UCZ9",
      "postalCode": "JOU0/fxFetg99zlnWrSDFZKnZFT9WK2EzlXVqkb5HIx3",
      "cvv": "5Lnrcofjmbmf+rUU+MXTZtSIR3fTDntEPfCsAil8yA=="
    },
    {
      "id": "CDC4",
      "title": "Auxiliary Card",
      "createdAt": "2026-02-28T16:09:55.568+01:00",
      "updatedAt": "2026-02-28T16:09:55.568+01:00",
      "allowedUsers": [],
      "cardHolderName": "DN6GSqYjrqDLCaJQlow2rbtOAsdkd/uS0Or5JBp3XR/1dc8hgf62pStWOo0=",
      "cardNumber": "EPEGjAJpyBuY/rAuW2bqzqjRPYVl5ctKNyoRTtB6tTkeeO4KjdzuKo14fic=",
      "expirationDate": "IAGmPnDX5BhJ/J/ynK/nGkQEe6ApUCljba413cAlvvWh",
      "postalCode": "e8tQgycMyeXQ8VjUkzL2w3Bg/+XKhOeLbayWs9bUwERs",
      "cvv": "VuhpQJYhXvhXbeitRFm5m4wxXQTXixvZhnKe3JpVtQ=="
    }
  ]
}"""

manager = VaultManager(user)
manager.upsert_vault_from_json_string(json_string)

# storable = manager.get_storable_by(internal_id="ACC0")
# manager.delete_storable(storable_id=storable.id)

# dicc = manager.export_vault_to_json(1)
# json_formateado = json.dumps(dicc, indent=2, ensure_ascii=False)

# print(json_formateado)