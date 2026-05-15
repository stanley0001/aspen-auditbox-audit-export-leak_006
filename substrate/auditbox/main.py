from fastapi import FastAPI

from auditbox.routes import audit as audit_routes
from auditbox.routes import auth as auth_routes


app = FastAPI(title="auditbox")
app.include_router(auth_routes.router)
app.include_router(audit_routes.router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
