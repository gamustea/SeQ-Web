import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from typing import Literal

from .model import (
    Account,
    BankAccount,
    CreditCard,
    Identity,
    SecureNote,
    SoftwareLicense,
    Storable,
    Vault,
    WifiNetwork,
)

from src.modules.users import User
from src.modules.infrastructure.unit_of_work import UnitOfWork
from src.modules.infrastructure.session import get_db_session

from .repositories import (
    VaultRepository,
    StorableRepository,
)

logger = logging.getLogger(__name__)

StorableKind = Literal[
    "account",
    "creditcard",
    "securenote",
    "identity",
    "bankaccount",
    "wifi",
    "license",
]


class VaultManager:
    """
    Gestor de almacenes (Vaults) y elementos almacenables (Storables).

    Toda la persistencia se realiza a través de los repositorios
    usando UnitOfWork. El manager no gestiona sesiones directamente.
    """

    def __init__(self, user: User) -> None:
        self.active_user = user

    @staticmethod
    def _parse_dt(value: Optional[str]) -> datetime:
        if not value:
            return datetime.now(timezone.utc).replace(tzinfo=None)
        try:
            dt = datetime.fromisoformat(value)
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except Exception as e:
            logger.warning("Failed to parse datetime value %r, defaulting to utcnow", value, exc_info=True)
            return datetime.now(timezone.utc).replace(tzinfo=None)

    def _ensure_vault_ownership(self, vault: Vault) -> None:
        if vault.user_id != self.active_user.id:
            raise PermissionError(
                f"El usuario {self.active_user.id} no es dueño del vault {vault.id}"
            )

    def get_vault_by_id(self, vault_id: int) -> Optional[Vault]:
        session = get_db_session()
        repo = VaultRepository(session=session)
        vault = repo.get_by_id(vault_id)
        if vault is None:
            logger.warning(f"Vault {vault_id} no encontrado")
            return None
        self._ensure_vault_ownership(vault)
        return vault

    def get_vault_for_user(self, is_recovery: bool = False) -> Optional[Vault]:
        session = get_db_session()
        repo = VaultRepository(session=session)
        vault = repo.get_by_user(self.active_user.id)
        return vault

    def upsert_vault_from_json(
        self,
        data: Dict[str, Any],
        is_recovery: bool = False,
    ) -> Tuple[Vault, bool]:
        try:
            algorithm = data.get("algorithm", {}) or {}

            with UnitOfWork() as uow:
                vault_repo = VaultRepository(uow)

                existing_vault = vault_repo.get_by_user(self.active_user.id)
                created = existing_vault is None

                if existing_vault is None:
                    vault = Vault(
                        user_id=self.active_user.id,
                        checker=data["checker"],
                        vault_key=data["vaultKey"],
                        transformation=algorithm.get("transformation", ""),
                        kdf=algorithm.get("kdf", ""),
                        kdf_iterations=int(algorithm.get("kdfIterations", 0)),
                        kdf_memory=int(algorithm.get("kdfMemoryKiB", 0)),
                        kdf_parallelism=int(algorithm.get("kdfParallelism", 1)),
                        salt=algorithm.get("salt", ""),
                    )
                    vault_repo.save(vault)
                    vault_id = vault.id
                else:
                    self._ensure_vault_ownership(existing_vault)
                    existing_vault.checker = data["checker"]
                    existing_vault.vault_key = data["vaultKey"]
                    existing_vault.transformation = algorithm.get("transformation", "")
                    existing_vault.kdf = algorithm.get("kdf", "")
                    existing_vault.kdf_iterations = int(algorithm.get("kdfIterations", 0))
                    existing_vault.kdf_memory = int(algorithm.get("kdfMemoryKiB", 0))
                    existing_vault.kdf_parallelism = int(algorithm.get("kdfParallelism", 1))
                    existing_vault.salt = algorithm.get("salt", "")

                    for st in list(existing_vault.storables):
                        uow.session.delete(st)
                    uow.session.flush()

                    vault_id = existing_vault.id

                accounts_data = []
                for acc in data.get("accounts", []) or []:
                    accounts_data.append({
                        "internal_id": acc.get("id"),
                        "title": acc.get("title"),
                        "created_at": self._parse_dt(acc.get("createdAt")),
                        "updated_at": self._parse_dt(acc.get("updatedAt")),
                        "username": acc.get("username", ""),
                        "domain": acc.get("domain", ""),
                        "password": acc.get("password", ""),
                    })

                creditcards_data = []
                for card in data.get("creditcards", []) or []:
                    creditcards_data.append({
                        "internal_id": card.get("id"),
                        "title": card.get("title"),
                        "created_at": self._parse_dt(card.get("createdAt")),
                        "updated_at": self._parse_dt(card.get("updatedAt")),
                        "cardholder_name": card.get("cardHolderName", ""),
                        "card_number": card.get("cardNumber", ""),
                        "expiration_date": card.get("expirationDate", ""),
                        "postal_code": card.get("postalCode", ""),
                        "cvv": card.get("cvv", ""),
                    })

                securenotes_data = []
                for note in data.get("securenotes", []) or []:
                    securenotes_data.append({
                        "internal_id": note.get("id"),
                        "title": note.get("title"),
                        "created_at": self._parse_dt(note.get("createdAt")),
                        "updated_at": self._parse_dt(note.get("updatedAt")),
                        "content": note.get("content", ""),
                    })

                identities_data = []
                for ident in data.get("identities", []) or []:
                    identities_data.append({
                        "internal_id": ident.get("id"),
                        "title": ident.get("title"),
                        "created_at": self._parse_dt(ident.get("createdAt")),
                        "updated_at": self._parse_dt(ident.get("updatedAt")),
                        "full_name": ident.get("fullName", ""),
                        "email": ident.get("email", ""),
                        "phone": ident.get("phone", ""),
                        "address": ident.get("address", ""),
                        "city": ident.get("city", ""),
                        "country": ident.get("country", ""),
                        "document_id": ident.get("documentId", ""),
                    })

                bankaccounts_data = []
                for bank in data.get("bankaccounts", []) or []:
                    bankaccounts_data.append({
                        "internal_id": bank.get("id"),
                        "title": bank.get("title"),
                        "created_at": self._parse_dt(bank.get("createdAt")),
                        "updated_at": self._parse_dt(bank.get("updatedAt")),
                        "bank_name": bank.get("bankName", ""),
                        "holder": bank.get("holder", ""),
                        "iban": bank.get("iban", ""),
                        "swift_bic": bank.get("swiftBic", ""),
                        "account_number": bank.get("accountNumber", ""),
                    })

                wifinetworks_data = []
                for wifi in data.get("wifinetworks", []) or []:
                    wifinetworks_data.append({
                        "internal_id": wifi.get("id"),
                        "title": wifi.get("title"),
                        "created_at": self._parse_dt(wifi.get("createdAt")),
                        "updated_at": self._parse_dt(wifi.get("updatedAt")),
                        "ssid": wifi.get("ssid", ""),
                        "password": wifi.get("password", ""),
                        "security_type": wifi.get("securityType", ""),
                    })

                licenses_data = []
                for lic in data.get("licenses", []) or []:
                    licenses_data.append({
                        "internal_id": lic.get("id"),
                        "title": lic.get("title"),
                        "created_at": self._parse_dt(lic.get("createdAt")),
                        "updated_at": self._parse_dt(lic.get("updatedAt")),
                        "product": lic.get("product", ""),
                        "license_key": lic.get("licenseKey", ""),
                        "licensed_to": lic.get("licensedTo", ""),
                        "version": lic.get("version", ""),
                    })

                vault = vault_repo.get_by_id(vault_id)
                if not vault:
                    raise ValueError(f"Vault {vault_id} no encontrado tras creación")

                for acc_data in accounts_data:
                    uow.session.add(Account(vault=vault, **acc_data))

                for cc_data in creditcards_data:
                    uow.session.add(CreditCard(vault=vault, **cc_data))

                for note_data in securenotes_data:
                    uow.session.add(SecureNote(vault=vault, **note_data))

                for ident_data in identities_data:
                    uow.session.add(Identity(vault=vault, **ident_data))

                for bank_data in bankaccounts_data:
                    uow.session.add(BankAccount(vault=vault, **bank_data))

                for wifi_data in wifinetworks_data:
                    uow.session.add(WifiNetwork(vault=vault, **wifi_data))

                for lic_data in licenses_data:
                    uow.session.add(SoftwareLicense(vault=vault, **lic_data))

            logger.info(
                f"Vault {vault.id} {'creado' if created else 'actualizado'} "
                f"para user {self.active_user.id} (is_recovery={is_recovery})"
            )
            return vault, created

        except IntegrityError as ie:
            logger.error(f"Error de integridad en upsert de vault: {ie}", exc_info=True)
            raise
        except Exception as e:
            logger.error(
                f"Error en upsert de vault desde JSON: {e}", exc_info=True
            )
            raise

    def upsert_vault_from_json_string(
        self,
        data: str,
        is_recovery: bool = False
    ):
        self.upsert_vault_from_json(
            json.loads(data),
            is_recovery
        )

    def export_vault_to_json(self, vault_id: int) -> Dict[str, Any]:
        session = get_db_session()
        repo = VaultRepository(session=session)
        vault = repo.get_by_id(vault_id)
        if vault is None:
            raise ValueError(f"Vault {vault_id} no encontrado")
        self._ensure_vault_ownership(vault)

        algorithm = {
            "transformation": vault.transformation,
            "kdf": vault.kdf,
            "kdfIterations": str(vault.kdf_iterations),
            "kdfMemoryKiB": str(vault.kdf_memory),
            "kdfParallelism": str(vault.kdf_parallelism),
            "salt": vault.salt,
        }

        accounts_json: List[Dict[str, Any]] = []
        cards_json: List[Dict[str, Any]] = []
        notes_json: List[Dict[str, Any]] = []
        identities_json: List[Dict[str, Any]] = []
        banks_json: List[Dict[str, Any]] = []
        wifis_json: List[Dict[str, Any]] = []
        licenses_json: List[Dict[str, Any]] = []

        for st in vault.storables:
            base = {
                "id": st.internal_id,
                "title": st.title,
            "createdAt": st.created_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ') if st.created_at else None,
            "updatedAt": st.updated_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ') if st.updated_at else None,
                "allowedUsers": [],
            }

            if isinstance(st, Account):
                accounts_json.append({
                    **base,
                    "username": st.username,
                    "domain": st.domain,
                    "password": st.password,
                })
            elif isinstance(st, CreditCard):
                cards_json.append({
                    **base,
                    "cardHolderName": st.cardholder_name,
                    "cardNumber": st.card_number,
                    "expirationDate": st.expiration_date,
                    "postalCode": st.postal_code,
                    "cvv": st.cvv,
                })
            elif isinstance(st, SecureNote):
                notes_json.append({
                    **base,
                    "content": st.content,
                })
            elif isinstance(st, Identity):
                identities_json.append({
                    **base,
                    "fullName": st.full_name,
                    "email": st.email,
                    "phone": st.phone,
                    "address": st.address,
                    "city": st.city,
                    "country": st.country,
                    "documentId": st.document_id,
                })
            elif isinstance(st, BankAccount):
                banks_json.append({
                    **base,
                    "bankName": st.bank_name,
                    "holder": st.holder,
                    "iban": st.iban,
                    "swiftBic": st.swift_bic,
                    "accountNumber": st.account_number,
                })
            elif isinstance(st, WifiNetwork):
                wifis_json.append({
                    **base,
                    "ssid": st.ssid,
                    "password": st.password,
                    "securityType": st.security_type,
                })
            elif isinstance(st, SoftwareLicense):
                licenses_json.append({
                    **base,
                    "product": st.product,
                    "licenseKey": st.license_key,
                    "licensedTo": st.licensed_to,
                    "version": st.version,
                })

        return {
            "checker": vault.checker,
            "vaultKey": vault.vault_key,
            "algorithm": algorithm,
            "accounts": accounts_json,
            "creditcards": cards_json,
            "securenotes": notes_json,
            "identities": identities_json,
            "bankaccounts": banks_json,
            "wifinetworks": wifis_json,
            "licenses": licenses_json,
        }

    def export_vault_to_json_string(self, vault_id: int) -> str:
        return str(self.export_vault_to_json(vault_id))

    def find_storables(
            self,
            *,
            vault_id: Optional[int] = None,
            limit: Optional[int] = None,
            **filters: Any,
        ) -> List[Storable]:
        session = get_db_session()
        repo = StorableRepository(session=session)

        if vault_id is not None:
            vault = self.get_vault_by_id(vault_id)
            if vault is None:
                return []
            storables = repo.get_by_vault(vault_id)
        else:
            storables = repo.get_by_user(self.active_user.id, limit or 100)

        result = storables
        for field, value in filters.items():
            if not hasattr(Storable, field):
                raise ValueError(f"Campo inválido para Storable: {field}")
            result = [s for s in result if getattr(s, field, None) == value]

        return result

    def get_storable_by(self, **filters: Any) -> Optional[Storable]:
        results = self.find_storables(limit=2, **filters)
        if not results:
            return None
        if len(results) > 1:
            raise ValueError(
                f"Más de un Storable coincide con los filtros: {filters!r}"
            )
        return results[0]

    def get_storable(self, storable_id: int) -> Optional[Storable]:
        return self.get_storable_by(id=storable_id)

    def list_storables(self, vault_id: int) -> List[Storable]:
        vault = self.get_vault_by_id(vault_id)
        if vault is None:
            return []
        return list(vault.storables)

    def add_storable_to_vault(
        self,
        vault_id: int,
        kind: StorableKind,
        *,
        internal_id: Optional[str] = None,
        title: Optional[str] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
        **payload: Any,
    ) -> Storable:
        vault = self.get_vault_by_id(vault_id)
        if vault is None:
            raise ValueError(f"Vault {vault_id} no encontrado")

        created_at = created_at or datetime.now(timezone.utc).replace(tzinfo=None)
        updated_at = updated_at or created_at

        if kind == "account":
            st = Account(
                vault=vault,
                internal_id=internal_id,
                title=title,
                created_at=created_at,
                updated_at=updated_at,
                username=payload.get("username", ""),
                domain=payload.get("domain", ""),
                password=payload.get("password", ""),
            )
        elif kind == "creditcard":
            st = CreditCard(
                vault=vault,
                internal_id=internal_id,
                title=title,
                created_at=created_at,
                updated_at=updated_at,
                cardholder_name=payload.get("cardholder_name", ""),
                card_number=payload.get("card_number", ""),
                expiration_date=payload.get("expiration_date", ""),
                postal_code=payload.get("postal_code", ""),
                cvv=payload.get("cvv", ""),
            )
        elif kind == "securenote":
            st = SecureNote(
                vault=vault,
                internal_id=internal_id,
                title=title,
                created_at=created_at,
                updated_at=updated_at,
                content=payload.get("content", ""),
            )
        elif kind == "identity":
            st = Identity(
                vault=vault,
                internal_id=internal_id,
                title=title,
                created_at=created_at,
                updated_at=updated_at,
                full_name=payload.get("full_name", ""),
                email=payload.get("email", ""),
                phone=payload.get("phone", ""),
                address=payload.get("address", ""),
                city=payload.get("city", ""),
                country=payload.get("country", ""),
                document_id=payload.get("document_id", ""),
            )
        elif kind == "bankaccount":
            st = BankAccount(
                vault=vault,
                internal_id=internal_id,
                title=title,
                created_at=created_at,
                updated_at=updated_at,
                bank_name=payload.get("bank_name", ""),
                holder=payload.get("holder", ""),
                iban=payload.get("iban", ""),
                swift_bic=payload.get("swift_bic", ""),
                account_number=payload.get("account_number", ""),
            )
        elif kind == "wifi":
            st = WifiNetwork(
                vault=vault,
                internal_id=internal_id,
                title=title,
                created_at=created_at,
                updated_at=updated_at,
                ssid=payload.get("ssid", ""),
                password=payload.get("password", ""),
                security_type=payload.get("security_type", ""),
            )
        elif kind == "license":
            st = SoftwareLicense(
                vault=vault,
                internal_id=internal_id,
                title=title,
                created_at=created_at,
                updated_at=updated_at,
                product=payload.get("product", ""),
                license_key=payload.get("license_key", ""),
                licensed_to=payload.get("licensed_to", ""),
                version=payload.get("version", ""),
            )
        else:
            raise ValueError(f"Tipo de storable no soportado: {kind}")

        try:
            with UnitOfWork() as uow:
                repo = StorableRepository(uow)
                repo.save(st)
            logger.info(f"Storable {st.id} creado en vault {vault_id}")
            return st
        except IntegrityError as ie:
            logger.error(f"Error de integridad añadiendo storable: {ie}", exc_info=True)
            raise
        except Exception as e:
            logger.error(f"Error añadiendo storable: {e}", exc_info=True)
            raise

    def update_storable(
        self,
        storable_id: int,
        *,
        title: Optional[str] = None,
        internal_id: Optional[str] = None,
        username: Optional[str] = None,
        domain: Optional[str] = None,
        password: Optional[str] = None,
        cardholder_name: Optional[str] = None,
        card_number: Optional[str] = None,
        expiration_date: Optional[str] = None,
        postal_code: Optional[str] = None,
        cvv: Optional[str] = None,
        content: Optional[str] = None,
        full_name: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        address: Optional[str] = None,
        city: Optional[str] = None,
        country: Optional[str] = None,
        document_id: Optional[str] = None,
        bank_name: Optional[str] = None,
        holder: Optional[str] = None,
        iban: Optional[str] = None,
        swift_bic: Optional[str] = None,
        account_number: Optional[str] = None,
        ssid: Optional[str] = None,
        security_type: Optional[str] = None,
        product: Optional[str] = None,
        license_key: Optional[str] = None,
        licensed_to: Optional[str] = None,
        version: Optional[str] = None,
    ) -> Storable:
        with UnitOfWork() as uow:
            repo = StorableRepository(uow)
            st = repo.get_by_id(storable_id)
            if st is None:
                raise ValueError(f"Storable {storable_id} no encontrado")

            try:
                changed = False
                if title is not None:
                    st.title = title
                    changed = True
                if internal_id is not None:
                    st.internal_id = internal_id
                    changed = True

                if isinstance(st, Account):
                    if username is not None:
                        st.username = username
                        changed = True
                    if domain is not None:
                        st.domain = domain
                        changed = True
                    if password is not None:
                        st.password = password
                        changed = True

                if isinstance(st, CreditCard):
                    if cardholder_name is not None:
                        st.cardholder_name = cardholder_name
                        changed = True
                    if card_number is not None:
                        st.card_number = card_number
                        changed = True
                    if expiration_date is not None:
                        st.expiration_date = expiration_date
                        changed = True
                    if postal_code is not None:
                        st.postal_code = postal_code
                        changed = True
                    if cvv is not None:
                        st.cvv = cvv
                        changed = True

                if isinstance(st, SecureNote):
                    if content is not None:
                        st.content = content
                        changed = True

                if isinstance(st, Identity):
                    if full_name is not None:
                        st.full_name = full_name
                        changed = True
                    if email is not None:
                        st.email = email
                        changed = True
                    if phone is not None:
                        st.phone = phone
                        changed = True
                    if address is not None:
                        st.address = address
                        changed = True
                    if city is not None:
                        st.city = city
                        changed = True
                    if country is not None:
                        st.country = country
                        changed = True
                    if document_id is not None:
                        st.document_id = document_id
                        changed = True

                if isinstance(st, BankAccount):
                    if bank_name is not None:
                        st.bank_name = bank_name
                        changed = True
                    if holder is not None:
                        st.holder = holder
                        changed = True
                    if iban is not None:
                        st.iban = iban
                        changed = True
                    if swift_bic is not None:
                        st.swift_bic = swift_bic
                        changed = True
                    if account_number is not None:
                        st.account_number = account_number
                        changed = True

                if isinstance(st, WifiNetwork):
                    if ssid is not None:
                        st.ssid = ssid
                        changed = True
                    if password is not None:
                        st.password = password
                        changed = True
                    if security_type is not None:
                        st.security_type = security_type
                        changed = True

                if isinstance(st, SoftwareLicense):
                    if product is not None:
                        st.product = product
                        changed = True
                    if license_key is not None:
                        st.license_key = license_key
                        changed = True
                    if licensed_to is not None:
                        st.licensed_to = licensed_to
                        changed = True
                    if version is not None:
                        st.version = version
                        changed = True

                if changed:
                    st.updated_at = datetime.utcnow()
                    repo.update(st)
                    logger.info(f"Storable {st.id} actualizado correctamente")
                else:
                    logger.info(f"Storable {st.id}: sin cambios")

                return st

            except IntegrityError as ie:
                logger.error(f"Error de integridad actualizando storable {storable_id}: {ie}", exc_info=True)
                raise
            except Exception as e:
                logger.error(
                    f"Error actualizando storable {storable_id}: {e}", exc_info=True
                )
                raise

    def bulk_update_storables(
        self,
        operations: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        vault_cache: Dict[bool, Optional[Vault]] = {}

        field_map = {
            "title": "title",
            "internalId": "internal_id",
            "username": "username",
            "domain": "domain",
            "password": "password",
            "cardHolderName": "cardholder_name",
            "cardNumber": "card_number",
            "expirationDate": "expiration_date",
            "postalCode": "postal_code",
            "cvv": "cvv",
            "content": "content",
            "fullName": "full_name",
            "email": "email",
            "phone": "phone",
            "address": "address",
            "city": "city",
            "country": "country",
            "documentId": "document_id",
            "bankName": "bank_name",
            "holder": "holder",
            "iban": "iban",
            "swiftBic": "swift_bic",
            "accountNumber": "account_number",
            "ssid": "ssid",
            "securityType": "security_type",
            "product": "product",
            "licenseKey": "license_key",
            "licensedTo": "licensed_to",
            "version": "version",
        }

        for op in operations:
            internal_id = op.get("internalId")
            is_recovery = bool(op.get("isRecovery", False))

            if not internal_id:
                results.append({
                    "internalId": None,
                    "isRecovery": is_recovery,
                    "status": "error",
                    "error": "Missing internalId",
                })
                continue

            changes = op.get("changes") or {}
            if not isinstance(changes, dict) or not changes:
                results.append({
                    "internalId": internal_id,
                    "isRecovery": is_recovery,
                    "status": "skipped",
                    "error": "No changes provided",
                })
                continue

            try:
                if is_recovery not in vault_cache:
                    vault_cache[is_recovery] = self.get_vault_for_user(
                        is_recovery=is_recovery
                    )

                vault = vault_cache[is_recovery]
                if not vault:
                    results.append({
                        "internalId": internal_id,
                        "isRecovery": is_recovery,
                        "status": "vault_not_found",
                    })
                    continue

                st = self.get_storable_by(
                    vault_id=vault.id,
                    internal_id=internal_id,
                )
                if not st:
                    results.append({
                        "internalId": internal_id,
                        "isRecovery": is_recovery,
                        "status": "not_found",
                    })
                    continue

                update_kwargs: Dict[str, Any] = {}
                for json_field, value in changes.items():
                    if json_field not in field_map:
                        continue
                    update_kwargs[field_map[json_field]] = value

                if not update_kwargs:
                    results.append({
                        "internalId": internal_id,
                        "isRecovery": is_recovery,
                        "status": "skipped",
                        "error": "No valid fields to update",
                    })
                    continue

                self.update_storable(st.id, **update_kwargs)
                results.append({
                    "internalId": internal_id,
                    "isRecovery": is_recovery,
                    "status": "updated",
                })

            except Exception as e:
                logger.error(
                    f"Error aplicando cambios al storable {internal_id} "
                    f"(is_recovery={is_recovery}): {e}",
                    exc_info=True,
                )
                results.append({
                    "internalId": internal_id,
                    "isRecovery": is_recovery,
                    "status": "error",
                    "error": str(e),
                })

        return results

    def delete_storable(self, storable_id: int) -> bool:
        st = self.get_storable(storable_id)
        if st is None:
            return False

        try:
            with UnitOfWork() as uow:
                repo = StorableRepository(uow)
                repo.delete(st)
            logger.info(f"Storable {storable_id} eliminado")
            return True
        except Exception as e:
            logger.error(f"Error eliminando storable {storable_id}: {e}", exc_info=True)
            raise
