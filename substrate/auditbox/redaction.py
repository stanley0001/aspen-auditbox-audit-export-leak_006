from typing import Any, Dict

from auditbox.models import AuditEvent


# Sensitive columns — never visible to a non-admin viewer.
SENSITIVE_FIELDS = (
    "actor_ip",
    "request_payload_hash",
    "internal_correlation_id",
    "redacted_secret_preview",
)


def redact_for_viewer(event: AuditEvent, viewer_role: str) -> Dict[str, Any]:
    """Return a dict view of `event` with sensitive fields stripped for non-admins.

    Admins receive the full record. The returned mapping is the canonical
    shape both the JSON and CSV serialization paths are meant to consume.
    """
    base: Dict[str, Any] = {
        "event_id": event.event_id,
        "actor_username": event.actor_username,
        "event_type": event.event_type,
        "created_at": event.created_at,
    }
    if viewer_role == "ADMIN":
        base["actor_ip"] = event.actor_ip
        base["request_payload_hash"] = event.request_payload_hash
        base["internal_correlation_id"] = event.internal_correlation_id
        base["redacted_secret_preview"] = event.redacted_secret_preview
    return base
