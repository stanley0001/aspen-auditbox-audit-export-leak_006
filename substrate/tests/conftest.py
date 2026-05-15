from typing import Callable, Dict

import pytest
from fastapi.testclient import TestClient

from auditbox import auth, models
from auditbox.main import app


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset stores + tokens between tests so order does not matter."""
    models.users.reset()
    models.events.reset()
    models.seed(models.users, models.events)
    auth._clear_tokens()
    yield


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture()
def admin_token(client: TestClient) -> str:
    r = client.post(
        "/auth/login",
        json={"username": "root", "password": "root123"},
    )
    assert r.status_code == 200, r.text
    return r.json()["token"]


@pytest.fixture()
def viewer_token(client: TestClient) -> str:
    r = client.post(
        "/auth/login",
        json={"username": "alice", "password": "alice123"},
    )
    assert r.status_code == 200, r.text
    return r.json()["token"]


@pytest.fixture()
def other_tenant_admin_token(client: TestClient) -> str:
    r = client.post(
        "/auth/login",
        json={"username": "otheradmin", "password": "other123"},
    )
    assert r.status_code == 200, r.text
    return r.json()["token"]


@pytest.fixture()
def auth_header() -> Callable[[str], Dict[str, str]]:
    def _h(token: str) -> Dict[str, str]:
        return {"Authorization": f"Bearer {token}"}
    return _h
