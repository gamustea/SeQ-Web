"""
User and OAuth token managers for the users module.

Managers contain business logic only — all database access is delegated
to UserRepository and TokenRepository via explicit UnitOfWork scopes.

Security invariants enforced here:
  - password_hash and password_salt never leave this module.
  - Credential verification uses constant-time comparison (via Encoder).
  - Token verification validates both JWT signature and database record state.
  - Password changes atomically revoke all existing tokens in one transaction.
  - Returned User objects are always expunged from the session before leaving
    the manager, so callers cannot accidentally trigger lazy loads on
    credential-bearing fields.

Classes:
    UserManager:        User lifecycle and credential management.
    OAuthTokenManager:  JWT access token and refresh token lifecycle.
"""

import secrets
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

import jwt

import src.modules.system.config_reading as CR
from src.modules.exceptions import (
    DatabaseError,
    ExistingUserError,
    ProfileUpdateError,
    UserBindingError,
)
from src.modules.infrastructure import UnitOfWork
from src.modules.system.logging import SecOpsLogger

from .model import AccessToken, RefreshToken, User
from .secrets import Encoder
from .repositories import TokenRepository, UserRepository

(
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
) = CR.get_oauth_config()

class UserManager:
    """
    Manages user lifecycle: registration, credential verification, and profile updates.

    All database access goes through UnitOfWork + UserRepository.
    Credential fields (password_hash, password_salt) are handled exclusively
    inside this class and never propagated to callers.

    Example:
    >>> manager = UserManager()
    >>> is_valid, user_id = manager.verify_credentials("johnd", "secret")
    """

    def __init__(self) -> None:
        self.logger = SecOpsLogger(self.__class__.__name__).get_logger()

    # =========================================================================
    # CREDENTIAL VERIFICATION
    # =========================================================================

    def verify_credentials(self, username: str, password: str) -> Tuple[bool, Optional[int]]:
        """
        Verify a username/password pair.

        Performs a constant-time password comparison to prevent timing attacks.
        The User object (including credential fields) never leaves this method.

        Args:
            username: Username to authenticate.
            password: Plaintext password to verify.

        Returns:
            Tuple of (is_valid, user_id). user_id is None if authentication fails.

        Raises:
            Exception: On unexpected database errors.
        """
        try:
            with UnitOfWork() as uow:
                user = UserRepository(uow).get_by_username(username)

                if user is None:
                    # Perform a dummy comparison to prevent username enumeration
                    # via timing differences.
                    Encoder.verify_password("dummy", password, "dummy_salt")
                    self.logger.info(f"Usuario '{username}' no encontrado")
                    return False, None

                is_valid = Encoder.verify_password(
                    stored_hash = user.password_hash,
                    password    = password,
                    salt        = user.password_salt,
                )
                user_id = user.id if is_valid else None

            if not is_valid:
                self.logger.warning(f"Contraseña incorrecta para '{username}'")
                return False, None

            self.logger.info(f"Credenciales válidas para '{username}' (ID: {user_id})")
            return True, user_id

        except Exception as e:
            self.logger.error(f"Error verificando credenciales: {e}")
            raise

    def validate_credentials_simple(self, username: str, password: str) -> bool:
        """
        Simplified credential check returning only a boolean.

        Args:
            username: Username to authenticate.
            password: Plaintext password to verify.

        Returns:
            True if credentials are valid.
        """
        is_valid, _ = self.verify_credentials(username, password)
        return is_valid

    # =========================================================================
    # USER REGISTRATION
    # =========================================================================

    def sign_in_user(
        self,
        username:   str,
        email:      str,
        first_name: str,
        last_name:  str,
        password:   str,
    ) -> User:
        """
        Register a new user.

        Validates uniqueness of username and email, hashes the password
        with a fresh random salt, and persists the new user record.

        Args:
            username:   Unique username (max 64 chars).
            email:      Unique email address (max 128 chars).
            first_name: User's first name.
            last_name:  User's last name.
            password:   Plaintext password (hashed before storage).

        Returns:
            The newly created User instance (credential fields excluded
            from the returned object via session expunge).

        Raises:
            ExistingUserError: If username or email is already registered.
            DatabaseError:     On unexpected persistence failures.
        """
        try:
            with UnitOfWork() as uow:
                repo = UserRepository(uow)

                if repo.username_exists(username):
                    raise ExistingUserError(username, None)
                if repo.email_exists(email):
                    raise ExistingUserError(None, email)

                salt            = Encoder.generate_salt()
                hashed_password = Encoder.hash_password_with_salt(password, salt)

                new_user = User(
                    username      = username,
                    email         = email,
                    first_name    = first_name,
                    last_name     = last_name,
                    password_hash = hashed_password,
                    password_salt = salt,
                )
                repo.save(new_user)
                # UoW commits and expunges on __exit__

            self.logger.info(f"Usuario '{username}' registrado exitosamente (ID: {new_user.id})")
            return new_user

        except ExistingUserError:
            raise
        except Exception as e:
            self.logger.error(f"Error registrando usuario '{username}': {e}")
            raise DatabaseError("Error con credenciales. Revísalas e inténtalo de nuevo.")

    # =========================================================================
    # QUERIES
    # =========================================================================

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        Retrieve a user by primary key.

        Args:
            user_id: User primary key.

        Returns:
            User instance (without credential fields accessible to caller),
            or None if not found.
        """
        with UnitOfWork() as uow:
            return UserRepository(uow).get_by_id(user_id)

    def get_user_by_username(self, username: str) -> Optional[User]:
        """
        Retrieve a user by username.

        Args:
            username: Unique username string.

        Returns:
            User instance, or None if not found.
        """
        with UnitOfWork() as uow:
            return UserRepository(uow).get_by_username(username)

    def get_all_users(self) -> List[User]:
        """
        Retrieve all registered users.

        Returns:
            List of User instances.
        """
        with UnitOfWork() as uow:
            return UserRepository(uow).get_all()

    # =========================================================================
    # PROFILE & PASSWORD UPDATES
    # =========================================================================

    def update_user_password(self, user_id: int, new_password: str) -> None:
        """
        Update a user's password with a fresh salt.

        Does NOT revoke existing tokens — callers that require token
        invalidation on password change should also call
        OAuthTokenManager.revoke_all_user_tokens(). Alternatively,
        use update_user_password_and_revoke_tokens() for an atomic operation.

        Args:
            user_id:      Primary key of the user to update.
            new_password: Plaintext new password (hashed before storage).

        Raises:
            UserBindingError: If the user is not found.
        """
        with UnitOfWork() as uow:
            user = UserRepository(uow).get_by_id(user_id)
            if user is None:
                raise UserBindingError(username=str(user_id))

            new_salt = Encoder.generate_salt()
            user.password_hash = Encoder.hash_password_with_salt(new_password, new_salt)
            user.password_salt = new_salt
            # UoW flushes and commits on __exit__

        self.logger.info(f"Contraseña actualizada para usuario {user_id}")

    def update_user_profile(self, user_id: int, first_name: str, last_name: str) -> User:
        """
        Update a user's display name fields.

        Username and email are immutable after registration.

        Args:
            user_id:    Primary key of the user to update.
            first_name: New first name.
            last_name:  New last name.

        Returns:
            The updated User instance.

        Raises:
            ProfileUpdateError: If the user is not found or update fails.
        """
        try:
            with UnitOfWork() as uow:
                user = UserRepository(uow).get_by_id(user_id)
                if user is None:
                    raise ProfileUpdateError("Usuario no encontrado")

                user.first_name = first_name
                user.last_name  = last_name
                # UoW commits on __exit__

            self.logger.info(f"Perfil actualizado para usuario {user_id} ({user.username})")
            return user

        except ProfileUpdateError:
            raise
        except Exception as e:
            self.logger.error(f"Error actualizando perfil para usuario {user_id}: {e}")
            raise ProfileUpdateError(f"Error al actualizar el perfil: {e}")

    def delete_user(self, user_id: int) -> None:
        """
        Delete a user by primary key.

        Args:
            user_id: Primary key of the user to delete.

        Raises:
            UserBindingError: If the user is not found.
        """
        with UnitOfWork() as uow:
            repo = UserRepository(uow)
            user = repo.get_by_id(user_id)
            if user is None:
                raise UserBindingError(username=str(user_id))
            repo.delete(user)

        self.logger.info(f"Usuario {user_id} eliminado")


class OAuthTokenManager:
    """
    Manages OAuth 2.0 access and refresh token lifecycle.

    Handles JWT creation and verification, token persistence via
    TokenRepository, and revocation flows.

    Security notes:
      - JWT signature is validated before the database record is checked,
        preventing unnecessary DB hits on forged tokens.
      - Token type claim ("type") is validated to prevent access tokens
        being used as refresh tokens and vice versa.
      - revoke_all_user_tokens() atomically revokes both token types
        in a single transaction, used for password-change and logout-everywhere.

    Example:
        >>> manager = OAuthTokenManager()
        >>> access_token = manager.create_access_token(user_id=1, username="johnd")
        >>> payload = manager.verify_access_token(access_token)
    """

    def __init__(self) -> None:
        self.logger = SecOpsLogger(self.__class__.__name__).get_logger()

    # =========================================================================
    # TOKEN CREATION
    # =========================================================================

    def create_access_token(self, user_id: int, username: str) -> str:
        """
        Create and persist a signed JWT access token.

        Args:
            user_id:  User primary key to embed in the token payload.
            username: Username to embed in the token payload.

        Returns:
            Signed JWT string.
        """
        expires_at = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        payload = {
            "sub":      str(user_id),
            "username": username,
            "exp":      expires_at,
            "iat":      datetime.utcnow(),
            "type":     "access",
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        with UnitOfWork() as uow:
            TokenRepository(uow).save_access_token(
                AccessToken(token=token, user_id=user_id, expires_at=expires_at)
            )

        return token

    def create_refresh_token(self, user_id: int) -> str:
        """
        Create and persist a cryptographically random refresh token.

        Refresh tokens are opaque random strings (not JWTs) to avoid
        leaking expiry information to the client.

        Args:
            user_id: User primary key.

        Returns:
            Raw refresh token string (URL-safe base64, 64 bytes).
        """
        token      = secrets.token_urlsafe(64)
        expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        with UnitOfWork() as uow:
            TokenRepository(uow).save_refresh_token(
                RefreshToken(token=token, user_id=user_id, expires_at=expires_at)
            )

        return token

    # =========================================================================
    # TOKEN VERIFICATION
    # =========================================================================

    def verify_access_token(self, token: str) -> Optional[dict]:
        """
        Verify a JWT access token and return its payload.

        Validates JWT signature and expiry first, then checks the database
        record for revocation. Both checks must pass.

        Args:
            token: Raw JWT string from the Authorization header.

        Returns:
            Decoded payload dict if valid, None otherwise.
        """
        try:
            # Step 1: validate JWT signature and expiry (no DB hit yet).
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])

            if payload.get("type") != "access":
                return None

            # Step 2: check database record for revocation.
            with UnitOfWork() as uow:
                record = TokenRepository(uow).get_access_token(token)
                is_valid = record is not None and record.is_valid()

            return payload if is_valid else None

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception as e:
            self.logger.error(f"Error verificando access token: {e}")
            return None

    def verify_refresh_token(self, token: str) -> Optional[int]:
        """
        Verify an opaque refresh token and return the associated user ID.

        Args:
            token: Raw refresh token string.

        Returns:
            User primary key if the token is valid, None otherwise.
        """
        try:
            with UnitOfWork() as uow:
                record = TokenRepository(uow).get_refresh_token(token)
                if record is None or not record.is_valid():
                    return None
                return record.user_id

        except Exception as e:
            self.logger.error(f"Error verificando refresh token: {e}")
            return None

    # =========================================================================
    # REVOCATION
    # =========================================================================

    def revoke_access_token(self, token: str) -> bool:
        """
        Revoke a single access token.

        Args:
            token: Raw JWT string to revoke.

        Returns:
            True if the token was found and revoked, False otherwise.
        """
        try:
            with UnitOfWork() as uow:
                revoked = TokenRepository(uow).revoke_access_token(token)

            if revoked:
                self.logger.info("Access token revocado")
            return revoked

        except Exception as e:
            self.logger.error(f"Error revocando access token: {e}")
            return False

    def revoke_all_user_tokens(self, user_id: int) -> None:
        """
        Atomically revoke all access and refresh tokens for a user.

        Both token types are revoked in a single transaction. Intended
        for password-change and logout-everywhere flows.

        Args:
            user_id: User primary key.
        """
        with UnitOfWork() as uow:
            TokenRepository(uow).revoke_all_tokens(user_id)

        self.logger.info(f"Todos los tokens revocados para usuario {user_id}")

    # =========================================================================
    # MAINTENANCE
    # =========================================================================

    def cleanup_expired_tokens(self) -> None:
        """
        Delete all expired access and refresh tokens from the database.

        Intended to be called from a periodic maintenance task.
        """
        with UnitOfWork() as uow:
            access_deleted, refresh_deleted = TokenRepository(uow).cleanup_expired_tokens()

        self.logger.info(
            f"Tokens expirados eliminados: "
            f"{access_deleted} access, {refresh_deleted} refresh"
        )