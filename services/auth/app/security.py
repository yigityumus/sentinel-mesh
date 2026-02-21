from datetime import datetime, timedelta, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from jose import jwt
from .settings import settings

# Argon2id by default in argon2-cffi’s PasswordHasher
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def create_access_token(*, user_id: int, role: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=settings.ACCESS_TOKEN_TTL_MIN)

    payload = {
        "sub": str(user_id),
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALG)
