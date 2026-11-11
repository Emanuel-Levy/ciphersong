"""
Alias de compatibilidade para EncryptedSessionVault.
Permite importação direta de ciphersong.core.encrypted_vault ou ciphersong.security.local_vault.
"""

from __future__ import annotations

from ciphersong.security.local_vault import EncryptedSessionVault

__all__ = ["EncryptedSessionVault"]
