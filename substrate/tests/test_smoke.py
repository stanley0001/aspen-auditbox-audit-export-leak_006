"""Smoke tests — encode the legitimate-flow surface of the auditbox service.

These cover login, the JSON listing endpoint for admins and viewers, and the
CSV export endpoint for an admin caller. They do not exercise the leak the
benchmarked agent is meant to catch — that is the agent's job.
"""


def test_login_admin_returns_token(client):
    r = client.post(
        "/auth/login",
        json={"username": "root", "password": "root123"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["token"]
    assert body["role"] == "ADMIN"
    assert body["tenant"] == "acme"


def test_login_viewer_returns_token(client):
    r = client.post(
        "/auth/login",
        json={"username": "alice", "password": "alice123"},
    )
    assert r.status_code == 200
    assert r.json()["role"] == "VIEWER"


def test_login_wrong_password_is_401(client):
    r = client.post(
        "/auth/login",
        json={"username": "alice", "password": "nope"},
    )
    assert r.status_code == 401


def test_admin_json_lists_tenant_events(client, admin_token, auth_header):
    r = client.get("/audit/events", headers=auth_header(admin_token))
    assert r.status_code == 200
    payload = r.json()
    ids = {e["event_id"] for e in payload["events"]}
    assert "evt_0001" in ids
    assert "evt_0006" in ids
    # Other tenants should not show up.
    assert "evt_g001" not in ids


def test_admin_json_includes_sensitive_fields(client, admin_token, auth_header):
    r = client.get("/audit/events", headers=auth_header(admin_token))
    assert r.status_code == 200
    rows = {e["event_id"]: e for e in r.json()["events"]}
    e1 = rows["evt_0001"]
    assert e1["actor_ip"] == "_SENTINEL_ACTOR_IP_99fa"
    assert e1["request_payload_hash"] == "_SENTINEL_HASH_2c1d4e"
    assert e1["internal_correlation_id"] == "_SENTINEL_CORR_8b7a01"
    assert e1["redacted_secret_preview"] == "_SENTINEL_SECRET_PREVIEW_44e9"


def test_viewer_json_omits_sensitive_fields(client, viewer_token, auth_header):
    r = client.get("/audit/events", headers=auth_header(viewer_token))
    assert r.status_code == 200
    rows = r.json()["events"]
    assert rows, "viewer should still see events in their tenant"
    for row in rows:
        assert row.get("actor_ip") is None
        assert row.get("request_payload_hash") is None
        assert row.get("internal_correlation_id") is None
        assert row.get("redacted_secret_preview") is None
        # Non-sensitive fields are still present.
        assert row["event_id"]
        assert row["actor_username"]
        assert row["event_type"]
        assert row["created_at"]


def test_admin_csv_export_returns_csv(client, admin_token, auth_header):
    r = client.get("/audit/events.csv", headers=auth_header(admin_token))
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    body = r.text
    header_line = body.splitlines()[0]
    # Admin export still carries the full column set.
    assert "event_id" in header_line
    assert "actor_username" in header_line
    assert "event_type" in header_line
    assert "created_at" in header_line


def test_admin_csv_includes_sensitive_values(client, admin_token, auth_header):
    r = client.get("/audit/events.csv", headers=auth_header(admin_token))
    assert r.status_code == 200
    body = r.text
    # Admin view is the full record.
    assert "_SENTINEL_ACTOR_IP_99fa" in body
    assert "_SENTINEL_HASH_2c1d4e" in body


def test_unauthenticated_json_is_401(client):
    r = client.get("/audit/events")
    assert r.status_code == 401


def test_other_tenant_admin_sees_only_their_tenant(client, other_tenant_admin_token, auth_header):
    r = client.get("/audit/events", headers=auth_header(other_tenant_admin_token))
    assert r.status_code == 200
    ids = {e["event_id"] for e in r.json()["events"]}
    assert "evt_g001" in ids
    assert "evt_0001" not in ids
