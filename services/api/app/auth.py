from fastapi import Depends, HTTPException, status, Request
from jose import jwt, JWTError
from .settings import settings


def get_bearer_token(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    return auth.removeprefix("Bearer ").strip()


def get_current_user(token: str = Depends(get_bearer_token)) -> dict:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # minimal claims validation
    sub = payload.get("sub")
    role = payload.get("role")
    if not sub or not role:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token claims")

    return {"user_id": sub, "role": role}


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return user