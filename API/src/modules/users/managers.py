import secrets
from datetime import datetime, timedelta
from typing import Any, List, Optional, Tuple

import jwt
from sqlalchemy.orm import Session

from src.modules.exceptions import DatabaseError, ExistingUserError, UserBindingError
from src.modules.misc import ConfigReader
from src.modules.shared import BaseManager

from .secrets import Encoder
from .model import User, AccessToken, RefreshToken

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

    def sign_in_user(
        self, 
        username: str,
        email: str,
        first_name: str,
        last_name: str,
        password: str       
    ) -> User:
        self._check_session()

        try:
            username_exists = self._exists(User, "username", username)
            email_exists    = self._exists(User, "email", email)

            if username_exists or email_exists:
                raise ExistingUserError(
                    username if username_exists else None, 
                    email if email_exists else None
                )

            password_salt = Encoder.generate_salt()
            hashed_password = Encoder.hash_password_with_salt(password, password_salt)

            new_user = User(
                username        = username,
                email           = email,
                first_name      = first_name,
                last_name       = last_name,
                password_hash   = hashed_password,
                password_salt   = password_salt,
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

    def update_user_password(self, user_id: int, new_password: str) -> None:
        self._check_session()

        user = self.get_user_by_id(user_or_id)
        if not user:
            raise UserBindingError(username=str(user_or_id))

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

    def delete_user(self, user: User) -> None:
        self._delete(user, "Usuario")



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
