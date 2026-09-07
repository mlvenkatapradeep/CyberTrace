from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityIncident:
    """Represents a security incident detected by CyberTrace."""

    incident_id: str
    detection_type: str
    severity: str
    source_ip: str
    username: str
    service: str
    first_seen: datetime
    last_seen: datetime
    attempt_count: int
    evidence: list[str]
    duration_seconds: float
    successful_login: bool
    successful_login_time: datetime | None
