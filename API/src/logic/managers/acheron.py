import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from typing import Literal

from src.core.model import (
    Account,
    CreditCard,
    Storable,
    User,
    Vault,
)

from ._base import BaseManager

StorableKind = Literal["account", "creditcard"]


class VaultManager(BaseManager):
    """
    Gestor de almacenes (Vaults) y elementos almacenables (Storables).
    """

    def __init__(self, user: User, session: Optional[Session] = None):
        super().__init__(session)
        self.active_user = user

    @staticmethod
    def _parse_dt(value: Optional[str]) -> datetime:
        if not value:
            return datetime.utcnow()
        try:
            return datetime.fromisoformat(value)
        except Exception:
            return datetime.utcnow()

    def _ensure_vault_ownership(self, vault: Vault) -> None:
        if vault.user_id != self.active_user.id:
            raise PermissionError(
                f"El usuario {self.active_user.id} no es dueño del vault {vault.id}"
            )

    def get_vault_by_id(self, vault_id: int) -> Optional[Vault]:
        self._check_session()
        vault = self.session.get(Vault, vault_id)
        if vault is None:
            self.logger.warning(f"Vault {vault_id} no encontrado")
            return None
        self._ensure_vault_ownership(vault)
        return vault

    def get_vault_for_user(self, is_recovery: bool = False) -> Optional[Vault]:
        self._check_session()
        vault = (
            self.session.query(Vault)
            .filter(
                Vault.user_id == self.active_user.id,
                Vault.is_recovery == is_recovery,
            )
            .one_or_none()
        )
        return vault

    def upsert_vault_from_json(
        self,
        data: Dict[str, Any],
        is_recovery: bool = False,
    ) -> Tuple[Vault, bool]:
        self._check_session()

        try:
            algorithm = data.get("algorithm", {}) or {}

            vault = self.get_vault_for_user(is_recovery=is_recovery)
            created = vault is None

            if vault is None:
                vault = Vault(
                    user_id=self.active_user.id,
                    is_recovery=is_recovery,
                    checker=data["checker"],
                    vault_key=data["vaultKey"],
                    transformation=algorithm.get("transformation", ""),
                    kdf=algorithm.get("kdf", ""),
                    kdf_iterations=int(algorithm.get("kdfIterations", 0)),
                    kdf_memory=int(algorithm.get("kdfMemoryKiB", 0)),
                    kdf_parallelism=int(algorithm.get("kdfParallelism", 1)),
                    salt=algorithm.get("salt", ""),
                )
                self.session.add(vault)
                self.session.flush()
            else:
                self._ensure_vault_ownership(vault)
                vault.checker = data["checker"]
                vault.vault_key = data["vaultKey"]
                vault.transformation = algorithm.get("transformation", "")
                vault.kdf = algorithm.get("kdf", "")
                vault.kdf_iterations = int(algorithm.get("kdfIterations", 0))
                vault.kdf_memory = int(algorithm.get("kdfMemoryKiB", 0))
                vault.kdf_parallelism = int(algorithm.get("kdfParallelism", 1))
                vault.salt = algorithm.get("salt", "")

                for st in list(vault.storables):
                    self.session.delete(st)
                self.session.flush()

            for acc in data.get("accounts", []) or []:
                created_at = self._parse_dt(acc.get("createdAt"))
                updated_at = self._parse_dt(acc.get("updatedAt"))

                account = Account(
                    vault=vault,
                    internal_id=acc.get("id"),
                    title=acc.get("title"),
                    created_at=created_at,
                    updated_at=updated_at,
                    username=acc.get("username", ""),
                    domain=acc.get("domain", ""),
                    password=acc.get("password", ""),
                )
                self.session.add(account)

            for card in data.get("creditcards", []) or []:
                created_at = self._parse_dt(card.get("createdAt"))
                updated_at = self._parse_dt(card.get("updatedAt"))

                cc = CreditCard(
                    vault=vault,
                    internal_id=card.get("id"),
                    title=card.get("title"),
                    created_at=created_at,
                    updated_at=updated_at,
                    cardholder_name=card.get("cardHolderName", ""),
                    card_number=card.get("cardNumber", ""),
                    expiration_date=card.get("expirationDate", ""),
                    postal_code=card.get("postalCode", ""),
                    cvv=card.get("cvv", ""),
                )
                self.session.add(cc)

            self._safe_commit()
            self.session.refresh(vault)

            self.logger.info(
                f"Vault {vault.id} {'creado' if created else 'actualizado'} "
                f"para user {self.active_user.id} (is_recovery={is_recovery})"
            )
            return vault, created

        except IntegrityError as ie:
            self._safe_rollback()
            self.logger.error(f"Error de integridad en upsert de vault: {ie}")
            raise
        except Exception as e:
            self._safe_rollback()
            self.logger.error(
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
        vault = self.get_vault_by_id(vault_id)
        if vault is None:
            raise ValueError(f"Vault {vault_id} no encontrado")

        self._check_session()

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

        for st in vault.storables:
            base = {
                "id": st.internal_id,
                "title": st.title,
                "createdAt": st.created_at.isoformat() if st.created_at else None,
                "updatedAt": st.updated_at.isoformat() if st.updated_at else None,
                "allowedUsers": [],
            }

            if isinstance(st, Account):
                accounts_json.append(
                    {
                        **base,
                        "username": st.username,
                        "domain": st.domain,
                        "password": st.password,
                    }
                )
            elif isinstance(st, CreditCard):
                cards_json.append(
                    {
                        **base,
                        "cardHolderName": st.cardholder_name,
                        "cardNumber": st.card_number,
                        "expirationDate": st.expiration_date,
                        "postalCode": st.postal_code,
                        "cvv": st.cvv,
                    }
                )

        return {
            "checker": vault.checker,
            "vaultKey": vault.vault_key,
            "algorithm": algorithm,
            "accounts": accounts_json,
            "creditcards": cards_json,
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
        self._check_session()

        query = self.session.query(Storable)

        if vault_id is not None:
            vault = self.get_vault_by_id(vault_id)
            if vault is None:
                return []
            query = query.filter(Storable.vault_id == vault_id)
        else:
            query = query.join(Vault).filter(Vault.user_id == self.active_user.id)

        for field, value in filters.items():
            if not hasattr(Storable, field):
                raise ValueError(f"Campo inválido para Storable: {field}")
            query = query.filter(getattr(Storable, field) == value)

        if limit is not None:
            query = query.limit(limit)

        return query.all()

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
        self._check_session()
        vault = self.get_vault_by_id(vault_id)
        if vault is None:
            raise ValueError(f"Vault {vault_id} no encontrado")

        created_at = created_at or datetime.utcnow()
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
        else:
            raise ValueError(f"Tipo de storable no soportado: {kind}")

        try:
            self.session.add(st)
            self._safe_commit()
            self.session.refresh(st)
            self.logger.info(f"Storable {st.id} creado en vault {vault_id}")
            return st
        except IntegrityError as ie:
            self._safe_rollback()
            self.logger.error(f"Error de integridad añadiendo storable: {ie}")
            raise
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error añadiendo storable: {e}", exc_info=True)
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
    ) -> Storable:
        self._check_session()
        st = self.get_storable(storable_id)
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

            if changed:
                st.updated_at = datetime.utcnow()
                self.session.add(st)
                self._safe_commit()
                self.session.refresh(st)
                self.logger.info(f"Storable {st.id} actualizado correctamente")
            else:
                self.logger.info(f"Storable {st.id}: sin cambios")

            return st

        except IntegrityError as ie:
            self._safe_rollback()
            self.logger.error(f"Error de integridad actualizando storable {storable_id}: {ie}")
            raise
        except Exception as e:
            self._safe_rollback()
            self.logger.error(
                f"Error actualizando storable {storable_id}: {e}", exc_info=True
            )
            raise

    def bulk_update_storables(
        self,
        operations: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        self._check_session()

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
                self.logger.error(
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
        self._check_session()
        st = self.get_storable(storable_id)
        if st is None:
            return False

        try:
            self.session.delete(st)
            self._safe_commit()
            self.logger.info(f"Storable {storable_id} eliminado")
            return True
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error eliminando storable {storable_id}: {e}", exc_info=True)
            raise
