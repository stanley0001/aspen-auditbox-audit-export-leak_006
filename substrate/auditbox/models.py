from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class User:
    username: str
    password: str
    role: str = "VIEWER"  # VIEWER | ADMIN
    tenant: str = "default"

    @property
    def is_admin(self) -> bool:
        return self.role == "ADMIN"


@dataclass
class AuditEvent:
    event_id: str
    tenant: str
    actor_username: str
    event_type: str
    created_at: str
    # Fields below are sensitive and must be redacted for non-admin viewers.
    actor_ip: str = ""
    request_payload_hash: str = ""
    internal_correlation_id: str = ""
    redacted_secret_preview: str = ""


class EventStore:
    def __init__(self) -> None:
        self._events: List[AuditEvent] = []

    def add(self, ev: AuditEvent) -> None:
        self._events.append(ev)

    def list_for_tenant(self, tenant: str) -> List[AuditEvent]:
        return [e for e in self._events if e.tenant == tenant]

    def list_all(self) -> List[AuditEvent]:
        return list(self._events)

    def reset(self) -> None:
        self._events.clear()


class UserStore:
    def __init__(self) -> None:
        self._users: Dict[str, User] = {}

    def add(self, u: User) -> None:
        self._users[u.username] = u

    def get(self, username: str) -> Optional[User]:
        return self._users.get(username)

    def reset(self) -> None:
        self._users.clear()


users = UserStore()
events = EventStore()


def seed(user_store: UserStore, event_store: EventStore) -> None:
    user_store.add(User(username="root", password="root123", role="ADMIN", tenant="acme"))
    user_store.add(User(username="alice", password="alice123", role="VIEWER", tenant="acme"))
    user_store.add(User(username="bob", password="bob123", role="VIEWER", tenant="acme"))
    user_store.add(User(username="otheradmin", password="other123", role="ADMIN", tenant="globex"))
    user_store.add(User(username="trent", password="trent123", role="VIEWER", tenant="globex"))

    # Sentinel-recognisable values so tests can assert on raw byte presence.
    event_store.add(AuditEvent(
        event_id="evt_0001",
        tenant="acme",
        actor_username="alice",
        event_type="LOGIN",
        created_at="2025-10-01T08:14:21+00:00",
        actor_ip="_SENTINEL_ACTOR_IP_99fa",
        request_payload_hash="_SENTINEL_HASH_2c1d4e",
        internal_correlation_id="_SENTINEL_CORR_8b7a01",
        redacted_secret_preview="_SENTINEL_SECRET_PREVIEW_44e9",
    ))
    event_store.add(AuditEvent(
        event_id="evt_0002",
        tenant="acme",
        actor_username="root",
        event_type="KEY_ROTATED",
        created_at="2025-10-01T09:02:08+00:00",
        actor_ip="10.0.4.21",
        request_payload_hash="a31f0c2d",
        internal_correlation_id="cor_a01",
        redacted_secret_preview="sk_live_***eb12",
    ))
    event_store.add(AuditEvent(
        event_id="evt_0003",
        tenant="acme",
        actor_username="root",
        event_type="PERMISSION_GRANTED",
        created_at="2025-10-01T10:18:55+00:00",
        actor_ip="10.0.4.21",
        request_payload_hash="b002eecf",
        internal_correlation_id="cor_a02",
        redacted_secret_preview="",
    ))
    event_store.add(AuditEvent(
        event_id="evt_0004",
        tenant="acme",
        actor_username="bob",
        event_type="LOGIN",
        created_at="2025-10-02T07:55:11+00:00",
        actor_ip="192.168.4.18",
        request_payload_hash="c9e102aa",
        internal_correlation_id="cor_a03",
        redacted_secret_preview="",
    ))
    event_store.add(AuditEvent(
        event_id="evt_0005",
        tenant="acme",
        actor_username="alice",
        event_type="REPORT_VIEWED",
        created_at="2025-10-02T11:30:42+00:00",
        actor_ip="192.168.4.91",
        request_payload_hash="ddc31178",
        internal_correlation_id="cor_a04",
        redacted_secret_preview="",
    ))
    event_store.add(AuditEvent(
        event_id="evt_0006",
        tenant="acme",
        actor_username="root",
        event_type="SETTINGS_UPDATED",
        created_at="2025-10-03T14:21:08+00:00",
        actor_ip="10.0.4.21",
        request_payload_hash="ef912004",
        internal_correlation_id="cor_a05",
        redacted_secret_preview="",
    ))

    # A different tenant (globex), used by tenancy regression guards.
    event_store.add(AuditEvent(
        event_id="evt_g001",
        tenant="globex",
        actor_username="otheradmin",
        event_type="LOGIN",
        created_at="2025-10-01T12:00:00+00:00",
        actor_ip="10.99.1.4",
        request_payload_hash="aa00bb11",
        internal_correlation_id="cor_g01",
        redacted_secret_preview="sk_g_***1122",
    ))
    event_store.add(AuditEvent(
        event_id="evt_g002",
        tenant="globex",
        actor_username="trent",
        event_type="REPORT_VIEWED",
        created_at="2025-10-02T09:30:00+00:00",
        actor_ip="10.99.1.7",
        request_payload_hash="cc22dd33",
        internal_correlation_id="cor_g02",
        redacted_secret_preview="",
    ))


seed(users, events)
