from dataclasses import dataclass
from datetime import datetime


@dataclass
class AuthenticationEvent:
    event_id: str
    timestamp: datetime
    event_type: str
    username: str | None
    source_ip: str | None
    source_port: int | None
    service: str
    success: bool
    raw_message: str
