import csv
import io
from typing import List

from fastapi import APIRouter, Depends, Response

from auditbox.auth import current_user
from auditbox.models import AuditEvent, User, events
from auditbox.redaction import redact_for_viewer
from auditbox.schemas import AuditEventView, AuditEventsResponse


router = APIRouter(prefix="/audit", tags=["audit"])


CSV_COLUMNS = [
    "event_id",
    "actor_username",
    "event_type",
    "created_at",
    "actor_ip",
    "request_payload_hash",
    "internal_correlation_id",
    "redacted_secret_preview",
]


def _scoped_events(caller: User) -> List[AuditEvent]:
    # Admins see their own tenant; viewers also scoped to tenant.
    return events.list_for_tenant(caller.tenant)


@router.get("/events", response_model=AuditEventsResponse)
def list_events(caller: User = Depends(current_user)) -> AuditEventsResponse:
    rows = _scoped_events(caller)
    redacted = [redact_for_viewer(e, caller.role) for e in rows]
    return AuditEventsResponse(events=[AuditEventView(**r) for r in redacted])


@router.get("/events.csv")
def export_csv(caller: User = Depends(current_user)) -> Response:
    rows = _scoped_events(caller)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for ev in rows:
        writer.writerow(ev.__dict__)
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_events.csv"},
    )
