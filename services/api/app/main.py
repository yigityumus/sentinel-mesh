from fastapi import FastAPI, Depends
from .auth import get_current_user, require_admin

app = FastAPI(title="api-service")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/me")
def me(user: dict = Depends(get_current_user)):
    return user


@app.get("/admin/stats")
def admin_stats(admin: dict = Depends(require_admin)):
    # placeholder stats for now
    return {
        "message": "admin ok",
        "admin_user_id": admin["user_id"],
        "stats": {
            "users_total": 1,
            "alerts_total": 0,
        },
    }
