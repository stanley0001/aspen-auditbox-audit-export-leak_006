from typing import List, Optional

from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    username: str
    role: str
    tenant: str


class AuditEventView(BaseModel):
    event_id: str
    actor_username: str
    event_type: str
    created_at: str
    # Sensitive fields are Optional; the JSON serializer omits them for non-admins.
    actor_ip: Optional[str] = None
    request_payload_hash: Optional[str] = None
    internal_correlation_id: Optional[str] = None
    redacted_secret_preview: Optional[str] = None


class AuditEventsResponse(BaseModel):
    events: List[AuditEventView]
