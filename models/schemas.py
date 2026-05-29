"""
Pydantic models — unified schema returned by all /api/* endpoints.
The frontend only needs to handle one shape regardless of indicator type.
"""

from typing import Literal, Optional
from pydantic import BaseModel


class ThreatResult(BaseModel):
    # Core
    value:          str
    type:           Literal["ip", "domain", "hash"]
    score:          int                         # 0–100 risk score
    verdict:        Literal["MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"]
    tags:           list[str] = []
    sources:        list[str] = []
    details:        str = ""
    cached:         bool = False

    # Common optional fields
    reports:        int = 0
    last_seen:      Optional[str] = None

    # IP-specific
    country:        Optional[str] = None
    asn:            Optional[str] = None
    open_ports:     list[int] = []

    # Domain-specific
    registrar:      Optional[str] = None
    created:        Optional[str] = None

    # Hash-specific
    filetype:       Optional[str] = None
    file_size:      Optional[str] = None
    malware_family: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    timestamp: int
