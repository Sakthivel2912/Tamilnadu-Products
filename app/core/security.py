import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple, Union

from fastapi import Request
import jwt as pyjwt
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


def create_access_token(*, user_id: str, role: str, jwt_secret: str, expires_days: int = 7) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        # Keep compatibility with earlier Node code that used `userId`.
        "userId": user_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=expires_days)).timestamp()),
    }
    return pyjwt.encode(payload, jwt_secret, algorithm="HS256")


def extract_bearer_token(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization")
    if not auth:
        return None
    if not auth.startswith("Bearer "):
        return None
    return auth.split(" ", 1)[1].strip()


def decode_token(token: str, *, jwt_secret: str) -> Dict[str, Any]:
    return pyjwt.decode(token, jwt_secret, algorithms=["HS256"])


def public_user_profile(doc: Dict[str, Any]) -> Dict[str, Any]:
    user = serialize_document(doc)
    for k in [
        "password",
        "password_hash",
        "resetPasswordToken",
        "resetPasswordExpires",
        "emailVerificationToken",
        "emailVerificationExpires",
    ]:
        user.pop(k, None)
    return user


def serialize_document(obj: Any) -> Any:
    if isinstance(obj, datetime):
        # Let FastAPI's jsonable_encoder handle datetime, but keep a stable fallback.
        return obj.isoformat()

    if isinstance(obj, dict):
        return {k: serialize_document(v) for k, v in obj.items()}

    if isinstance(obj, list):
        return [serialize_document(v) for v in obj]

    return obj


def safe_int_id(value: Union[str, int, None]) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (ValueError, TypeError):
        return None


def razorpay_signature_matches(secret: str, *, order_id: str, payment_id: str, signature: str) -> bool:
    # Razorpay spec: HMAC-SHA256(order_id + "|" + payment_id)
    body = f"{order_id}|{payment_id}"
    digest = hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, signature)


def get_token_user_id_role(decoded: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    user_id = decoded.get("userId") or decoded.get("id")
    role = decoded.get("role")
    return user_id, role

