
import os
import hashlib
import jwt
import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple
from src.core.model import User, AccessToken, RefreshToken
from src.persistence import UserDBManager
from src.misc.configread import ConfigReader

config_reader = ConfigReader()
(ACCESS_TOKEN_EXPIRE_MINUTES, 
 REFRESH_TOKEN_EXPIRE_DAYS, 
 JWT_SECRET_KEY, 
 JWT_ALGORITHM) = config_reader.get_oauth_config()


class Encoder:
    
    @staticmethod
    def encode_sha256(input_string: str) -> str:
        """Encodes the input string using SHA-256 and returns the hexadecimal digest.
        Args:
            input_string (str): The string to be encoded.
        Returns:
            str: The SHA-256 hexadecimal digest of the input string.
        """
        hasher = hashlib.sha256()
        hasher.update(input_string.encode('utf-8'))
        return hasher.hexdigest()
    
    @staticmethod
    def generate_salt() -> str:
        """Generates a random salt for hashing.
        Returns:
            str: A randomly generated salt (32 hex characters).
        """
        return os.urandom(16).hex()  # 16 bytes es el tamaño recomendado
    
    @staticmethod
    def hash_password_with_salt(password: str, salt: str) -> str:
        """Combines a password with a salt and returns the SHA-256 hash.
        
        Args:
            password (str): The plaintext password to hash.
            salt (str): The salt to combine with the password.
        
        Returns:
            str: The SHA-256 hexadecimal digest of the salted password.
        """
        # CORREGIDO: salt primero previene ataques de precomputación
        salted_password = salt + password
        return Encoder.encode_sha256(salted_password)
    
    @staticmethod
    def verify_password(stored_hash: str, password: str, salt: str) -> bool:
        """Verifies if a password matches the stored hash.
        
        Args:
            stored_hash (str): The hash stored in the database.
            password (str): The password to verify.
            salt (str): The salt used for the stored hash.
        
        Returns:
            bool: True if password is correct, False otherwise.
        """
        return Encoder.hash_password_with_salt(password, salt) == stored_hash


class OAuthTokenManager:
    """Gestor de tokens OAuth 2.0 usando JWT"""
    
    def __init__(self):
        self.db = UserDBManager()
    
    def create_access_token(self, user_id: int, username: str) -> str:
        """Crea un JWT access token"""
        expires_at = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        payload = {
            "sub": str(user_id),  # subject (user ID)
            "username": username,
            "exp": expires_at,  # expiration time
            "iat": datetime.utcnow(),  # issued at
            "type": "access"
        }
        
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        # Guardar en DB
        access_token_record = AccessToken(
            token=token,
            user_id=user_id,
            expires_at=expires_at
        )
        self.db.session.add(access_token_record)
        self.db._safe_commit()
        
        return token
    
    def create_refresh_token(self, user_id: int) -> str:
        """Crea un refresh token opaco (no JWT)"""
        token = secrets.token_urlsafe(64)
        expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        
        refresh_token_record = RefreshToken(
            token=token,
            user_id=user_id,
            expires_at=expires_at
        )
        self.db.session.add(refresh_token_record)
        self.db._safe_commit()
        
        return token
    
    def verify_access_token(self, token: str) -> Optional[dict]:
        """
        Verifica y decodifica un access token.
        Returns: Payload del token si es válido, None si no lo es
        """
        try:
            # Decodificar JWT
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
            # Verificar tipo
            if payload.get("type") != "access":
                return None
            
            # Verificar si está revocado en DB
            token_record = self.db.session.query(AccessToken).filter(
                AccessToken.token == token
            ).one_or_none()
            
            if not token_record or not token_record.is_valid():
                return None
            
            return payload
        
        except jwt.ExpiredSignatureError:
            return None  # Token expirado
        except jwt.InvalidTokenError:
            return None  # Token inválido
        except Exception as e:
            return None
    
    def verify_refresh_token(self, token: str) -> Optional[int]:
        """
        Verifica un refresh token.
        Returns: user_id si es válido, None si no lo es
        """
        try:
            token_record = self.db.session.query(RefreshToken).filter(
                RefreshToken.token == token
            ).one_or_none()
            
            if not token_record or not token_record.is_valid():
                return None
            
            return token_record.user_id # type: ignore
        
        except Exception:
            return None
    
    def revoke_access_token(self, token: str) -> bool:
        """Revoca un access token"""
        try:
            token_record = self.db.session.query(AccessToken).filter(
                AccessToken.token == token
            ).one_or_none()
            
            if token_record:
                token_record.revoked = 1 # type: ignore
                self.db._safe_commit()
                return True
            return False
        except Exception:
            return False
    
    def revoke_all_user_tokens(self, user_id: int) -> None:
        """Revoca todos los tokens de un usuario"""
        try:
            self.db.session.query(AccessToken).filter(
                AccessToken.user_id == user_id
            ).update({"revoked": 1})
            
            self.db.session.query(RefreshToken).filter(
                RefreshToken.user_id == user_id
            ).update({"revoked": 1})
            
            self.db._safe_commit()
        except Exception as e:
            self.db._safe_rollback()
            raise
    
    def cleanup_expired_tokens(self) -> None:
        """Elimina tokens expirados de la DB (ejecutar periódicamente)"""
        try:
            now = datetime.utcnow()
            
            self.db.session.query(AccessToken).filter(
                AccessToken.expires_at < now
            ).delete()
            
            self.db.session.query(RefreshToken).filter(
                RefreshToken.expires_at < now
            ).delete()
            
            self.db._safe_commit()
        except Exception:
            self.db._safe_rollback()
