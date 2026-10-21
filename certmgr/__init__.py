"""Cert-Manager - lokale Verwaltung von Client-Zertifikaten.

Oeffentliche API:

    from certmgr import CertManager, Store, CloudflareClient

Siehe README.md fuer die Gesamtbeschreibung.
"""
__version__ = "1.0.0"

from .cfapi import CFError, CloudflareClient
from .manager import CertManager
from .store import Store

__all__ = [
    "CFError",
    "CertManager",
    "CloudflareClient",
    "Store",
    "__version__",
]
