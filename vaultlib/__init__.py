from __future__ import annotations

"""vaultlib — desktop reference implementation of the cryptowl vault.

Implements docs/design.md (key hierarchy, vault.meta, config.sig, SQLCipher
raw key) byte-exact for cross-verification with the Android app, and the
moments migration into an existing vault.
"""

from . import crockford32, crypto
from .vault import Vault

__all__ = ["crockford32", "crypto", "Vault"]
__version__ = "0.1.0"
