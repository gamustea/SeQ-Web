import secrets
from datetime import datetime, timedelta
from typing import Any, List, Optional, Tuple

import jwt
from sqlalchemy.orm import Session

from src.modules.exceptions import DatabaseError, ExistingUserError, UserBindingError
from src.modules.misc import ConfigReader
from src.modules.shared import BaseManager

from .secrets import Encoder
from .model import User, Person, AccessToken, RefreshToken

(
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
    JWT_SECRET_KEY,
    JWT_ALGORITHM
) = ConfigReader.get_oauth_config()


class UserManager(BaseManager):
    """
    Gestor completo para usuarios y personas con autenticación y gestión de tokens.
    """

    def verify_credentials(self, username: str, password: str) -> Tuple[bool, Optional[int]]:
        self._check_session()

        try:
            user = self._get_by_field(User, "username", username)

            if not user:
                self.logger.info(f"Usuario '{username}' no encontrado")
                return False, None

            valid_password = Encoder.verify_password(
                stored_hash=user.password_hash,
                password=password,
                salt=user.password_salt
            )

            if not valid_password:
                self.logger.warning(f"Contraseña incorrecta para '{username}'")
                return False, None

            user_id = user.id
            self.session.expunge(user)

            self.logger.info(f"Credenciales válidas para '{username}' (ID: {user_id})")
            return True, user_id

        except Exception as e:
            self.logger.error(f"Error verificando credenciales: {e}")
            raise

    def validate_credentials_simple(self, username: str, password: str) -> bool:
        is_valid, _ = self.verify_credentials(username, password)
        return is_valid

    def create_user(self, user: User) -> None:
        self._check_session()

        try:
            if self._exists(User, "username", user.username):
                raise ExistingUserError(username=user.username)

            if user.person_id:
                if not self._exists(Person, "id", user.person_id):
                    if user.person:
                        self._create_person(user.person)
            elif user.person:
                self._create_person(user.person)

            self.session.add(user)
            self._safe_commit()

            self.logger.info(f"Usuario '{user.username}' creado con ID {user.id}")

        except ExistingUserError:
            raise
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error creando usuario: {e}")
            raise

    def sign_in_user(self, username: str, password: str, email: str, alias: str) -> User:
        self._check_session()

        try:
            if self._exists(User, "username", username):
                raise ExistingUserError(username)

            person = self._get_by_field(Person, "alias", alias)

            if not person:
                raise UserBindingError(username=username, alias=alias)

            salt = Encoder.generate_salt()
            hashed_password = Encoder.hash_password_with_salt(password, salt)

            new_user = User(
                username=username,
                password_hash=hashed_password,
                password_salt=salt,
                email=email,
                person_id=person.id
            )

            self.session.add(new_user)
            self._safe_commit()
            self.session.expunge(new_user)

            self.logger.info(f"Usuario '{username}' registrado exitosamente")
            return new_user

        except (ExistingUserError, UserBindingError):
            self._safe_rollback()
            raise
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error registrando usuario: {e}")
            raise DatabaseError("Error con credenciales. Revísalas e inténtalo de nuevo.")

    def get_user_by_username(self, username: str) -> Optional[User]:
        return self._get_by_field(User, "username", username)

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        return self._get_by_field(User, "id", user_id)

    def get_all_users(self) -> List[User]:
        return self._get_all(User)

    def update_user_password(self, user_or_id, new_password: str) -> None:
        self._check_session()

        if isinstance(user_or_id, int):
            user = self.get_user_by_id(user_or_id)
            if not user:
                raise UserBindingError(username=str(user_or_id), alias="unknown")
        else:
            user = user_or_id

        try:
            new_salt = Encoder.generate_salt()
            new_hash = Encoder.hash_password_with_salt(new_password, new_salt)

            user.password_salt = new_salt
            user.password_hash = new_hash

            self.session.add(user)
            self._safe_commit()

            self.logger.info(f"Contraseña actualizada para usuario {user.id}")

        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error actualizando contraseña: {e}")
            raise

    def update_user_password_by_id(self, user_id: int, new_password: str) -> None:
        user = self.get_user_by_id(user_id)

        if not user:
            raise UserBindingError(username=str(user_id), alias="unknown")

        self.update_user_password(user, new_password)

    def delete_user(self, user: User) -> None:
        self._delete(user, "Usuario")

    def sign_in_person(self, first_name: str, last_name: str, alias: str) -> Person:
        self._check_session()

        try:
            if self._exists(Person, "alias", alias):
                raise ExistingUserError(f"El alias {alias} ya está en uso")

            person = Person(
                first_name=first_name,
                last_name=last_name,
                alias=alias
            )

            self._create_person(person)

            self.logger.info(f"Persona registrada: {first_name} {last_name}")
            return person

        except ExistingUserError:
            raise
        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error registrando persona: {e}")
            raise

    def get_person_by_alias(self, alias: str) -> Optional[Person]:
        return self._get_by_field(Person, "alias", alias)

    def get_person_by_email(self, email: str) -> Optional[Person]:
        return self._get_by_field(Person, "email", email)

    def get_person_by_id(self, person_id: int) -> Optional[Person]:
        return self._get_by_field(Person, "id", person_id)

    def get_all_people(self) -> List[Person]:
        return self._get_all(Person)

    def update_person(self, person: Person) -> None:
        self._check_session()

        try:
            existing = self.get_person_by_id(person.id)

            if existing:
                existing.first_name = person.first_name
                existing.last_name = person.last_name
                existing.email = person.email

                self._safe_commit()
                self.logger.info(f"Persona {person.id} actualizada")
            else:
                self.logger.warning(f"Persona {person.id} no encontrada")

        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error actualizando persona: {e}")
            raise

    def delete_person(self, person: Person) -> None:
        self._delete(person, "Persona")

    def _get_by_field(self, model, field: str, value: Any) -> Optional[Any]:
        self._check_session()

        try:
            obj = self.session.query(model).filter(
                getattr(model, field) == value
            ).one_or_none()

            if obj:
                self.logger.debug(f"{model.__name__} con {field}='{value}' encontrado")
            else:
                self.logger.debug(f"{model.__name__} con {field}='{value}' no encontrado")

            return obj

        except Exception as e:
            self.logger.error(f"Error obteniendo {model.__name__}: {e}")
            raise

    def _get_all(self, model) -> List[Any]:
        self._check_session()

        try:
            objects = self.session.query(model).all()
            self.logger.info(f"Se obtuvieron {len(objects)} {model.__name__}s")
            return objects

        except Exception as e:
            self.logger.error(f"Error obteniendo {model.__name__}s: {e}")
            raise

    def _exists(self, model, field: str, value: Any) -> bool:
        self._check_session()

        return self.session.query(model).filter(
            getattr(model, field) == value
        ).count() > 0

    def _delete(self, obj: Any, obj_type: str) -> None:
        self._check_session()

        try:
            self.session.delete(obj)
            self._safe_commit()

            self.logger.info(f"{obj_type} eliminado")

        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error eliminando {obj_type}: {e}")
            raise

    def _create_person(self, person: Person) -> None:
        self._check_session()

        try:
            self.session.add(person)
            self.session.flush()
            self.logger.info(
                f"Persona creada: {person.first_name} {person.last_name} (ID: {person.id})"
            )

        except Exception as e:
            self._safe_rollback()
            self.logger.error(f"Error creando persona: {e}")
            raise


class OAuthTokenManager(BaseManager):
    """Gestor de tokens OAuth 2.0 usando JWT"""

    def create_access_token(self, user_id: int, username: str) -> str:
        expires_at = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        payload = {
            "sub": str(user_id),
            "username": username,
            "exp": expires_at,
            "iat": datetime.utcnow(),
            "type": "access"
        }

        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        access_token_record = AccessToken(
            token=token,
            user_id=user_id,
            expires_at=expires_at
        )
        self.session.add(access_token_record)
        self._safe_commit()

        return token

    def create_refresh_token(self, user_id: int) -> str:
        token = secrets.token_urlsafe(64)
        expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        refresh_token_record = RefreshToken(
            token=token,
            user_id=user_id,
            expires_at=expires_at
        )
        self.session.add(refresh_token_record)
        self._safe_commit()

        return token

    def verify_access_token(self, token: str) -> Optional[dict]:
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])

            if payload.get("type") != "access":
                return None

            token_record = self.session.query(AccessToken).filter(
                AccessToken.token == token
            ).one_or_none()

            if not token_record or not token_record.is_valid():
                return None

            return payload

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception:
            return None

    def verify_refresh_token(self, token: str) -> Optional[int]:
        try:
            token_record = self.session.query(RefreshToken).filter(
                RefreshToken.token == token
            ).one_or_none()

            if not token_record or not token_record.is_valid():
                return None

            return token_record.user_id  # type: ignore

        except Exception:
            return None

    def revoke_access_token(self, token: str) -> bool:
        try:
            token_record = self.session.query(AccessToken).filter(
                AccessToken.token == token
            ).one_or_none()

            if token_record:
                token_record.revoked = 1  # type: ignore
                self._safe_commit()
                return True
            return False
        except Exception:
            return False

    def revoke_all_user_tokens(self, user_id: int) -> None:
        try:
            self.session.query(AccessToken).filter(
                AccessToken.user_id == user_id
            ).update({"revoked": 1})

            self.session.query(RefreshToken).filter(
                RefreshToken.user_id == user_id
            ).update({"revoked": 1})

            self._safe_commit()
        except Exception as e:
            self._safe_rollback()
            raise

    def cleanup_expired_tokens(self) -> None:
        try:
            now = datetime.utcnow()

            self.session.query(AccessToken).filter(
                AccessToken.expires_at < now
            ).delete()

            self.session.query(RefreshToken).filter(
                RefreshToken.expires_at < now
            ).delete()

            self._safe_commit()
        except Exception:
            self._safe_rollback()
