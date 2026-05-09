"""
src.modules.acheron - Módulo de gestión de secretos/vault

Exponente:
    - VaultManager: Gestión de bóvedas
    - Modelos: Vault, Storable, Account, CreditCard
    - Repositorios: VaultRepository, StorableRepository
    - Endpoints: acheron_bp
"""

from .model import (
    Account,
    CreditCard,
    Storable,
    Vault,
)
from .managers import VaultManager
from .repositories import (
    VaultRepository,
    StorableRepository
)
from .endpoints import acheron_bp
from .exceptions import (
    VaultError,
    VaultNotFoundError,
    StorableNotFoundError,
    StorableConflictError,
)

__all__ = [
    # Models
    "Account",
    "CreditCard",
    "Storable",
    "Vault",
    # Managers
    "VaultManager",
    # Repositories
    "VaultRepository",
    "StorableRepository",
    # Endpoints
    "acheron_bp",
    # Exceptions
    "VaultError",
    "VaultNotFoundError",
    "StorableNotFoundError",
    "StorableConflictError",
]