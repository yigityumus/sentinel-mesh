from fastapi import Depends, HTTPException, status, Request
from jose import jwt, JWTError

from .settings import settings
from .log_client import send_event


def client_ip(request: Request) -> str:
    return request.headers.get("x-real-ip") or (
        request.client.host if request.client else "unknown"
    )


def original_path(request: Request) -> str:
    return request.headers.get("x-original-uri") or str(request.url.path)


def get_bearer_token(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        send_event(
            event="missing_token",
            ip=client_ip(request),
            path=original_path(request),
            user_id=None,
            meta={},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing token",
        )

    return auth.removeprefix("Bearer ").strip()


def get_current_user(
    request: Request,
    token: str = Depends(get_bearer_token),
) -> dict:
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALG],
        )
    except JWTError:
        send_event(
            event="invalid_token",
            ip=client_ip(request),
            path=original_path(request),
            user_id=None,
            meta={},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    sub = payload.get("sub")
    role = payload.get("role")

    if not sub or not role:
        send_event(
            event="invalid_token_claims",
            ip=client_ip(request),
            path=original_path(request),
            user_id=None,
            meta={},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token claims",
        )

    return {"user_id": sub, "role": role}


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return user