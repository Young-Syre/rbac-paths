"""Offline Kubernetes RBAC privilege-escalation path finder.

Everything in this package is a pure function over JSON that was already
dumped to disk.  There is no API client here and no network code: see
``tests/test_no_network.py``, which parses every module in this package and
fails if a networking module is imported.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
