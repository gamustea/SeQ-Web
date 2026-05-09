
import os
import hashlib


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

def generate_salt() -> str:
    """Generates a random salt for hashing.
    Returns:
        str: A randomly generated salt (32 hex characters).
    """
    return os.urandom(16).hex()  # 16 bytes es el tamaño recomendado

def hash_password_with_salt(password: str, salt: str) -> str:
    """Combines a password with a salt and returns the SHA-256 hash.
    
    Args:
        password (str): The plaintext password to hash.
        salt (str): The salt to combine with the password.
    
    Returns:
        str: The SHA-256 hexadecimal digest of the salted password.
    """
    salted_password = salt + password
    return encode_sha256(salted_password)

def verify_password(stored_hash: str, password: str, salt: str) -> bool:
    """Verifies if a password matches the stored hash.
    
    Args:
        stored_hash (str): The hash stored in the database.
        password (str): The password to verify.
        salt (str): The salt used for the stored hash.
    
    Returns:
        bool: True if password is correct, False otherwise.
    """
    return hash_password_with_salt(password, salt) == stored_hash



