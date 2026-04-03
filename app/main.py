import json
import math
import os
import random
import secrets
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, Dict, List, Optional, Tuple

import jwt as pyjwt
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Select, and_, asc, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .database import configure_engine, get_session, init_db
from .db.models import Contact, Order, Product, ReturnRequest, User
from .core.security import (
    create_access_token,
    decode_token,
    extract_bearer_token,
    public_user_profile,
    razorpay_signature_matches,
    safe_int_id,
    serialize_document,
    get_token_user_id_role,
    hash_password,
    verify_password,
)

settings = get_settings()

_BACKEND_ROOT = Path(__file__).resolve().parent.parent
UPLOAD_DIR = str(_BACKEND_ROOT / settings["upload_dir"])
os.makedirs(UPLOAD_DIR, exist_ok=True)

configure_engine(settings)

app = FastAPI(title="Tamil Nadu Products API (FastAPI)")

app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

allowed_origins = [
    settings.get("frontend_url"),
    "https://divine-gentleness-production-7e46.up.railway.app",
]
allowed_origins = [o for o in allowed_origins if o]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SessionDep = Annotated[AsyncSession, Depends(get_session)]


@app.on_event("startup")
async def _startup() -> None:
    await init_db()


def _json_dumps(data: Any) -> str:
    return json.dumps(data, default=lambda x: x.isoformat() if isinstance(x, datetime) else str(x))


def _json_error(
    status_code: int,
    *,
    success: bool = False,
    message: Optional[str] = None,
    error: Optional[str] = None,
    details: Any = None,
) -> JSONResponse:
    payload: Dict[str, Any] = {"success": success}
    if message is not None:
        payload["message"] = message
    if error is not None:
        payload["error"] = error
    if details is not None:
        payload["details"] = details
    return JSONResponse(status_code=status_code, content=payload)


def user_orm_to_api_dict(u: User) -> Dict[str, Any]:
    address = None
    if u.address_json:
        try:
            address = json.loads(u.address_json)
        except json.JSONDecodeError:
            address = None
    return {
        "_id": u.id,
        "firstName": u.first_name,
        "lastName": u.last_name,
        "email": u.email,
        "phone": u.phone,
        "password": u.password_hash,
        "role": u.role,
        "isAdmin": u.is_admin,
        "isGoogleUser": u.is_google_user,
        "emailVerified": u.email_verified,
        "phoneVerified": u.phone_verified,
        "active": u.active,
        "address": address,
        "loginCount": u.login_count,
        "lastLogin": u.last_login,
        "createdAt": u.created_at,
        "updatedAt": u.updated_at,
    }


def product_orm_to_api_dict(p: Product) -> Dict[str, Any]:
    images = json.loads(p.images_json or "[]")
    sizes = json.loads(p.sizes_json or "[]")
    colors = json.loads(p.colors_json or "[]")
    tags = json.loads(p.tags_json or "[]")
    size_stock = json.loads(p.size_stock_json or "{}")
    seo = json.loads(p.seo_json) if p.seo_json else None
    specs = json.loads(p.specifications_json) if p.specifications_json else None
    return {
        "_id": p.id,
        "name": p.name,
        "slug": p.slug,
        "description": p.description,
        "shortDescription": p.short_description,
        "category": p.category,
        "price": p.price,
        "originalPrice": p.original_price,
        "images": images,
        "sizes": sizes,
        "colors": colors,
        "stock": p.stock,
        "sizeStock": size_stock,
        "rating": p.rating,
        "reviews": p.reviews,
        "tags": tags,
        "featured": p.featured,
        "active": p.active,
        "seo": seo,
        "specifications": specs,
        "createdAt": p.created_at,
        "updatedAt": p.updated_at,
    }


def order_orm_to_api_dict(o: Order, customer_embed: Any = None) -> Dict[str, Any]:
    items = json.loads(o.items_json or "[]")
    ship = json.loads(o.shipping_json or "{}")
    hist = json.loads(o.status_history_json or "[]")
    cust = o.customer_id if customer_embed is None else customer_embed
    return {
        "_id": o.id,
        "orderId": o.order_id,
        "customer": cust,
        "items": items,
        "shippingAddress": ship,
        "subtotal": o.subtotal,
        "total": o.total,
        "status": o.status,
        "paymentMethod": o.payment_method,
        "paymentStatus": o.payment_status,
        "paymentId": o.payment_id,
        "razorpayOrderId": o.razorpay_order_id,
        "razorpayPaymentId": o.razorpay_payment_id,
        "razorpaySignature": o.razorpay_signature,
        "trackingNumber": o.tracking_number,
        "estimatedDelivery": o.estimated_delivery,
        "actualDelivery": o.actual_delivery,
        "statusHistory": hist,
        "createdAt": o.created_at,
        "updatedAt": o.updated_at,
    }


async def _get_authenticated_user(
    request: Request, session: AsyncSession
) -> Tuple[Optional[Dict[str, Any]], Optional[JSONResponse]]:
    token = extract_bearer_token(request)
    if not token:
        return None, _json_error(401, error="Access denied. No token provided.")

    try:
        decoded = decode_token(token, jwt_secret=settings["jwt_secret"])
    except pyjwt.PyJWTError:
        return None, _json_error(401, error="Invalid token")

    user_id, _ = get_token_user_id_role(decoded)
    uid = safe_int_id(user_id)
    if uid is None:
        return None, _json_error(401, error="Invalid token")

    result = await session.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        return None, _json_error(401, error="User not found")

    if not user.active:
        return None, _json_error(401, error="Account is deactivated")

    return user_orm_to_api_dict(user), None


def _require_admin(user_doc: Dict[str, Any]) -> Optional[JSONResponse]:
    if not user_doc.get("isAdmin") and user_doc.get("role") != "admin":
        return _json_error(403, error="Access denied. Admin privileges required.")
    return None


class RegisterPayload(BaseModel):
    firstName: str
    lastName: str
    email: EmailStr
    phone: str
    password: str = Field(min_length=6)


class LoginPayload(BaseModel):
    email: EmailStr
    password: str


class ProfilePayload(BaseModel):
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    address: Optional[Dict[str, Any]] = None


class CreateOrderPayload(BaseModel):
    customerEmail: EmailStr
    products: List[Dict[str, Any]] = Field(min_length=1)
    totalAmount: float
    customerName: str
    customerPhone: str
    shippingAddress: Dict[str, Any]


class UpdateOrderStatusPayload(BaseModel):
    status: str
    note: Optional[str] = None


class CreatePaymentOrderPayload(BaseModel):
    amount: int
    orderId: str


class VerifyPaymentPayload(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str
    orderId: str


class ContactPayload(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = None
    subject: str
    message: str
    category: Optional[str] = "general"


class ReturnCreatePayload(BaseModel):
    orderId: str
    email: EmailStr
    items: List[Dict[str, Any]] = Field(default_factory=list)
    reason: str
    condition: str = "new"
    images: List[str] = Field(default_factory=list)
    notes: Optional[str] = None


def _product_list_filters(
    *,
    category: Optional[str],
    search: Optional[str],
    featured: Optional[str],
    min_price_raw: Optional[str],
    max_price_raw: Optional[str],
    size: Optional[str],
    color: Optional[str],
) -> List[Any]:
    conds: List[Any] = [Product.active.is_(True)]
    if category:
        conds.append(Product.category == category)
    if featured == "true":
        conds.append(Product.featured.is_(True))
    if search:
        term = f"%{search}%"
        conds.append(
            or_(
                Product.name.ilike(term),
                Product.description.ilike(term),
                Product.tags_json.ilike(term),
            )
        )
    if min_price_raw:
        conds.append(Product.price >= float(min_price_raw))
    if max_price_raw:
        conds.append(Product.price <= float(max_price_raw))
    if size:
        conds.append(Product.sizes_json.like(f"%\"{size}\"%"))
    if color:
        conds.append(Product.colors_json.like(f"%{color}%"))
    return conds


@app.get("/api/health")
async def health() -> JSONResponse:
    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": "Server is running",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "environment": settings.get("env"),
        },
    )


@app.post("/api/auth/register", status_code=201)
async def register(payload: RegisterPayload, session: SessionDep) -> JSONResponse:
    email = payload.email.lower()
    phone = payload.phone

    if (await session.execute(select(User).where(User.email == email))).scalar_one_or_none():
        return _json_error(400, message="Email already registered")
    if (await session.execute(select(User).where(User.phone == phone))).scalar_one_or_none():
        return _json_error(400, message="Phone number already registered")

    user = User(
        first_name=payload.firstName,
        last_name=payload.lastName,
        email=email,
        phone=phone,
        password_hash=hash_password(payload.password),
        role="customer",
    )
    session.add(user)
    await session.flush()
    await session.refresh(user)

    ud = user_orm_to_api_dict(user)
    token = create_access_token(
        user_id=str(user.id),
        role=user.role,
        jwt_secret=settings["jwt_secret"],
        expires_days=7,
    )

    return JSONResponse(
        status_code=201,
        content={
            "success": True,
            "message": "Registration successful",
            "data": {"user": public_user_profile(ud), "token": token, "role": user.role},
        },
    )


@app.post("/api/auth/login")
async def login(payload: LoginPayload, session: SessionDep) -> JSONResponse:
    email = payload.email.lower()
    result = await session.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        return _json_error(401, message="Invalid email or password")

    if not verify_password(payload.password, user.password_hash):
        return _json_error(401, message="Invalid email or password")

    if not user.active:
        return _json_error(401, message="Account is deactivated")

    now = datetime.now(timezone.utc)
    user.last_login = now
    user.login_count = user.login_count + 1
    session.add(user)

    ud = user_orm_to_api_dict(user)
    token = create_access_token(
        user_id=str(user.id),
        role=user.role,
        jwt_secret=settings["jwt_secret"],
        expires_days=7,
    )

    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": "Login successful",
            "data": {
                "user": public_user_profile(ud),
                "token": token,
                "role": user.role,
            },
        },
    )


@app.post("/api/auth/admin/login")
async def admin_login(payload: LoginPayload, session: SessionDep) -> JSONResponse:
    ADMIN_EMAIL = "admin@tamilnaduproducts.com"

    if payload.email.lower() != ADMIN_EMAIL:
        return _json_error(403, message="Access denied. Only admin can access this portal.")

    result = await session.execute(select(User).where(User.email == payload.email.lower(), User.role == "admin"))
    user = result.scalar_one_or_none()
    if not user:
        return _json_error(401, message="Invalid admin credentials")

    if not verify_password(payload.password, user.password_hash):
        return _json_error(401, message="Invalid admin credentials")

    if not user.active:
        return _json_error(401, message="Admin account is deactivated")

    now = datetime.now(timezone.utc)
    user.last_login = now
    user.login_count = user.login_count + 1
    session.add(user)

    ud = user_orm_to_api_dict(user)
    token = create_access_token(
        user_id=str(user.id),
        role="admin",
        jwt_secret=settings["jwt_secret"],
        expires_days=7,
    )

    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": "Admin login successful",
            "data": {"user": public_user_profile(ud), "token": token, "role": "admin"},
        },
    )


@app.get("/api/auth/me")
async def me(request: Request, session: SessionDep) -> JSONResponse:
    token = extract_bearer_token(request)
    if not token:
        return _json_error(401, message="No token provided")

    try:
        decoded = decode_token(token, jwt_secret=settings["jwt_secret"])
    except pyjwt.PyJWTError:
        return _json_error(401, message="Invalid token")

    user_id, _ = get_token_user_id_role(decoded)
    uid = safe_int_id(user_id)
    if uid is None:
        return _json_error(401, message="Invalid token")

    result = await session.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        return _json_error(401, message="User not found")

    ud = user_orm_to_api_dict(user)
    return JSONResponse(
        status_code=200,
        content={"success": True, "data": {"user": public_user_profile(ud), "role": user.role}},
    )


@app.post("/api/auth/logout")
async def logout() -> JSONResponse:
    return JSONResponse(status_code=200, content={"success": True, "message": "Logout successful"})


@app.put("/api/auth/profile")
async def update_profile(request: Request, payload: ProfilePayload, session: SessionDep) -> JSONResponse:
    user_doc, err = await _get_authenticated_user(request, session)
    if err:
        return err

    uid = int(user_doc["_id"])
    result = await session.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        return _json_error(401, message="User not found")

    if payload.firstName is not None:
        user.first_name = payload.firstName
    if payload.lastName is not None:
        user.last_name = payload.lastName
    if payload.phone is not None:
        user.phone = payload.phone
    if payload.email is not None:
        user.email = str(payload.email).lower()
    if payload.address is not None:
        user.address_json = _json_dumps(payload.address)
    session.add(user)

    ud = user_orm_to_api_dict(user)
    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "data": {"user": public_user_profile(ud), "message": "Profile updated successfully"},
        },
    )


@app.get("/api/orders/customer")
async def customer_orders(request: Request, session: SessionDep) -> JSONResponse:
    user_doc, err = await _get_authenticated_user(request, session)
    if err:
        return err

    cid = int(user_doc["_id"])
    result = await session.execute(select(Order).where(Order.customer_id == cid).order_by(desc(Order.created_at)).limit(200))
    rows = result.scalars().all()
    out = [order_orm_to_api_dict(o) for o in rows]
    return JSONResponse(status_code=200, content={"success": True, "data": {"orders": serialize_document(out)}})


@app.get("/api/products")
async def get_products(request: Request, session: SessionDep) -> JSONResponse:
    query_params = request.query_params
    page = int(query_params.get("page") or 1)
    limit = int(query_params.get("limit") or 12)
    category = query_params.get("category")
    search = query_params.get("search")
    sort = query_params.get("sort") or "featured"
    min_price_raw = query_params.get("minPrice")
    max_price_raw = query_params.get("maxPrice")
    size = query_params.get("size")
    color = query_params.get("color")
    featured = query_params.get("featured")

    conds = _product_list_filters(
        category=category,
        search=search,
        featured=featured,
        min_price_raw=min_price_raw,
        max_price_raw=max_price_raw,
        size=size,
        color=color,
    )
    where_clause = and_(*conds) if conds else True  # type: ignore[assignment]

    stmt: Select[Tuple[Product]] = select(Product).where(where_clause)
    if sort == "price-low":
        stmt = stmt.order_by(asc(Product.price))
    elif sort == "price-high":
        stmt = stmt.order_by(desc(Product.price))
    elif sort == "newest":
        stmt = stmt.order_by(desc(Product.created_at))
    elif sort == "rating":
        stmt = stmt.order_by(desc(Product.rating))
    elif sort == "name-asc":
        stmt = stmt.order_by(asc(Product.name))
    elif sort == "name-desc":
        stmt = stmt.order_by(desc(Product.name))
    else:
        stmt = stmt.order_by(desc(Product.featured), desc(Product.created_at))

    skip = (page - 1) * limit
    stmt = stmt.offset(skip).limit(limit)

    total_res = await session.execute(select(func.count()).select_from(Product).where(where_clause))
    total = int(total_res.scalar_one() or 0)

    res = await session.execute(stmt)
    products = res.scalars().all()
    docs = [product_orm_to_api_dict(p) for p in products]

    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "data": {
                "products": serialize_document(docs),
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total,
                    "pages": int(math.ceil(total / float(limit))) if limit else 1,
                },
            },
        },
    )


@app.get("/api/products/{product_id}")
async def get_product(product_id: str, session: SessionDep) -> JSONResponse:
    pid = safe_int_id(product_id)
    if pid is None:
        return _json_error(404, error="Product not found")

    result = await session.execute(select(Product).where(Product.id == pid))
    p = result.scalar_one_or_none()
    if not p:
        return _json_error(404, error="Product not found")

    return JSONResponse(status_code=200, content={"success": True, "data": serialize_document(product_orm_to_api_dict(p))})


def _generate_order_id() -> str:
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    timestamp36 = base36(now_ms)
    random_part = base36(int(random.random() * 1e9)).upper()[:5]
    return f"TNP{timestamp36}{random_part}".upper()


def base36(num: int) -> str:
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    if num < 0:
        return "-" + base36(-num)
    if num == 0:
        return "0"
    out = ""
    n = num
    while n:
        n, i = divmod(n, 36)
        out = digits[i] + out
    return out


@app.post("/api/orders/create-order", status_code=201)
async def create_guest_order(payload: CreateOrderPayload, session: SessionDep) -> JSONResponse:
    now = datetime.now(timezone.utc)

    customer_id: Optional[int] = None
    ur = await session.execute(select(User).where(User.email == payload.customerEmail.lower()))
    eu = ur.scalar_one_or_none()
    if eu:
        customer_id = eu.id

    order_id = _generate_order_id()

    items: List[Dict[str, Any]] = []
    for p in payload.products:
        pid = safe_int_id(p.get("productId"))
        items.append(
            {
                "product": pid if pid is not None else p.get("productId"),
                "name": p.get("name"),
                "price": p.get("price"),
                "quantity": p.get("quantity"),
                "size": p.get("size") or "M",
                "image": p.get("image"),
                "subtotal": (p.get("price") or 0) * (p.get("quantity") or 0),
            }
        )

    shipping_address: Dict[str, Any] = {
        "fullName": payload.customerName,
        "phone": payload.customerPhone,
        "email": payload.customerEmail.lower(),
        "country": "India",
        **payload.shippingAddress,
    }

    hist = [{"status": "ordered", "timestamp": now, "note": "Order placed successfully"}]
    order_row = Order(
        order_id=order_id,
        customer_id=customer_id,
        items_json=_json_dumps(items),
        shipping_json=_json_dumps(shipping_address),
        subtotal=payload.totalAmount,
        total=payload.totalAmount,
        status="ordered",
        payment_method="cod",
        payment_status="pending",
        status_history_json=_json_dumps(hist),
    )
    session.add(order_row)
    await session.flush()

    return JSONResponse(
        status_code=201,
        content={
            "success": True,
            "message": "Order created successfully",
            "data": {
                "orderId": order_id,
                "status": "ordered",
                "total": payload.totalAmount,
                "createdAt": now,
            },
        },
    )


@app.get("/api/orders/track-order/{order_id}")
async def track_order(order_id: str, session: SessionDep) -> JSONResponse:
    result = await session.execute(select(Order).where(Order.order_id == order_id.upper()))
    doc = result.scalar_one_or_none()
    if not doc:
        return _json_error(404, message="Order not found")

    o = order_orm_to_api_dict(doc)
    response_doc = serialize_document(
        {
            "orderId": o.get("orderId"),
            "status": o.get("status"),
            "total": o.get("total"),
            "createdAt": o.get("createdAt"),
            "items": o.get("items") or [],
            "shippingAddress": o.get("shippingAddress") or {},
            "paymentStatus": o.get("paymentStatus"),
            "paymentMethod": o.get("paymentMethod"),
            "statusHistory": o.get("statusHistory") or [],
            "trackingNumber": o.get("trackingNumber"),
            "estimatedDelivery": o.get("estimatedDelivery"),
        }
    )

    return JSONResponse(status_code=200, content={"success": True, "data": response_doc})


@app.get("/api/orders/status-options")
async def status_options() -> JSONResponse:
    opts = [
        {"value": "ordered", "label": "Ordered", "description": "Order has been placed"},
        {"value": "shipped", "label": "Shipped", "description": "Order has been shipped"},
        {"value": "out-for-delivery", "label": "Out for Delivery", "description": "Order is out for delivery"},
        {"value": "delivered", "label": "Delivered", "description": "Order has been delivered"},
    ]
    return JSONResponse(status_code=200, content={"success": True, "data": opts})


@app.put("/api/orders/update-order/{order_id}")
async def update_order_status(order_id: str, payload: UpdateOrderStatusPayload, session: SessionDep) -> JSONResponse:
    now = datetime.now(timezone.utc)

    if not payload.status:
        return _json_error(400, message="Validation errors", details=["status is required"])

    result = await session.execute(select(Order).where(Order.order_id == order_id.upper()))
    doc = result.scalar_one_or_none()
    if not doc:
        return _json_error(404, message="Order not found")

    valid_progressions = {
        "ordered": ["shipped"],
        "confirmed": ["shipped"],
        "shipped": ["out-for-delivery"],
        "out-for-delivery": ["delivered"],
        "delivered": [],
    }

    current_status = doc.status
    allowed = valid_progressions.get(current_status, [])
    if payload.status not in allowed:
        return _json_error(400, message=f"Cannot update status from {current_status} to {payload.status}")

    old_status = current_status
    doc.status = payload.status
    hist = json.loads(doc.status_history_json or "[]")
    hist.append(
        {
            "status": payload.status,
            "timestamp": now,
            "note": payload.note or f"Status updated from {old_status} to {payload.status}",
        }
    )
    doc.status_history_json = _json_dumps(hist)

    if payload.status == "shipped":
        doc.estimated_delivery = now + timedelta(days=5)
        doc.tracking_number = f"TRK{secrets.token_hex(5)[:10].upper()}"

    if payload.status == "delivered":
        doc.actual_delivery = now
        doc.payment_status = "completed"

    session.add(doc)

    o = order_orm_to_api_dict(doc)
    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": "Order status updated successfully",
            "data": {
                "orderId": o.get("orderId"),
                "status": o.get("status"),
                "trackingNumber": o.get("trackingNumber"),
                "estimatedDelivery": o.get("estimatedDelivery"),
                "actualDelivery": o.get("actualDelivery"),
                "updatedAt": o.get("updatedAt") or now,
            },
        },
    )


@app.post("/api/payments/create-order")
async def payments_create_order(payload: CreatePaymentOrderPayload, session: SessionDep) -> JSONResponse:
    razor_key_id = settings.get("razorpay_key_id")
    razor_key_secret = settings.get("razorpay_key_secret")
    if not razor_key_id or not razor_key_secret:
        return _json_error(500, error="Payment service not configured")

    result = await session.execute(select(Order).where(Order.order_id == payload.orderId.upper()))
    order_doc = result.scalar_one_or_none()
    if not order_doc:
        return _json_error(404, error="Order not found")

    from razorpay import Client as RazorpayClient

    rzp = RazorpayClient(auth=(razor_key_id, razor_key_secret))

    razorpay_order = rzp.order.create(
        {"amount": payload.amount, "currency": "INR", "receipt": order_doc.order_id, "notes": {"orderId": order_doc.order_id}}
    )

    order_doc.razorpay_order_id = razorpay_order.get("id")
    order_doc.payment_status = "processing"
    session.add(order_doc)

    return JSONResponse(status_code=200, content={"success": True, "data": razorpay_order})


@app.post("/api/payments/verify")
async def payments_verify(payload: VerifyPaymentPayload, session: SessionDep) -> JSONResponse:
    razor_key_secret = settings.get("razorpay_key_secret")
    if not razor_key_secret:
        return _json_error(500, error="Payment service not configured")

    result = await session.execute(select(Order).where(Order.order_id == payload.orderId.upper()))
    order_doc = result.scalar_one_or_none()
    if not order_doc:
        return _json_error(404, error="Order not found")

    is_valid = razorpay_signature_matches(
        razor_key_secret,
        order_id=payload.razorpay_order_id,
        payment_id=payload.razorpay_payment_id,
        signature=payload.razorpay_signature,
    )
    if not is_valid:
        return _json_error(400, error="Invalid payment signature")

    order_doc.payment_id = payload.razorpay_payment_id
    order_doc.razorpay_payment_id = payload.razorpay_payment_id
    order_doc.razorpay_signature = payload.razorpay_signature
    order_doc.payment_status = "completed"
    order_doc.status = "confirmed"
    session.add(order_doc)

    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": "Payment verified successfully",
            "data": {"orderId": order_doc.order_id, "paymentId": payload.razorpay_payment_id},
        },
    )


@app.post("/api/contact", status_code=201)
async def contact(payload: ContactPayload, session: SessionDep) -> JSONResponse:
    now = datetime.now(timezone.utc)
    cat = payload.category or "general"
    row = Contact(
        name=payload.name,
        email=str(payload.email).lower(),
        phone=payload.phone,
        subject=payload.subject,
        message=payload.message,
        category=cat,
    )
    session.add(row)
    await session.flush()
    await session.refresh(row)

    doc = {
        "name": row.name,
        "email": row.email,
        "phone": row.phone,
        "subject": row.subject,
        "message": row.message,
        "category": row.category,
        "createdAt": row.created_at,
        "updatedAt": row.updated_at,
    }
    return JSONResponse(
        status_code=201,
        content={
            "success": True,
            "data": serialize_document(doc),
            "message": "Contact request submitted successfully",
        },
    )


def _generate_return_id() -> str:
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    timestamp36 = base36(now_ms).upper()
    random_part = base36(int(random.random() * 1e9)).upper()[:5]
    return f"RET{timestamp36}{random_part}".upper()


@app.post("/api/returns", status_code=201)
async def create_return(payload: ReturnCreatePayload, session: SessionDep) -> JSONResponse:
    now = datetime.now(timezone.utc)
    return_id = _generate_return_id()

    ur = await session.execute(select(User).where(User.email == payload.email.lower()))
    user = ur.scalar_one_or_none()

    orow = await session.execute(select(Order).where(Order.order_id == payload.orderId.upper()))
    order_doc = orow.scalar_one_or_none()

    hist = [{"status": "pending", "timestamp": now, "note": "Return requested"}]
    row = ReturnRequest(
        return_id=return_id,
        order_pk=order_doc.id if order_doc else None,
        customer_id=user.id if user else None,
        items_json=_json_dumps(payload.items),
        reason=payload.reason,
        condition=payload.condition,
        images_json=_json_dumps(payload.images),
        notes=payload.notes,
        status_history_json=_json_dumps(hist),
    )
    session.add(row)
    await session.flush()
    await session.refresh(row)

    doc = {
        "returnId": row.return_id,
        "order": row.order_pk,
        "customer": row.customer_id,
        "items": json.loads(row.items_json or "[]"),
        "reason": row.reason,
        "condition": row.condition,
        "images": json.loads(row.images_json or "[]"),
        "notes": row.notes,
        "status": row.status,
        "refundMethod": row.refund_method,
        "statusHistory": json.loads(row.status_history_json or "[]"),
        "createdAt": row.created_at,
        "updatedAt": row.updated_at,
    }
    return JSONResponse(
        status_code=201,
        content={"success": True, "data": serialize_document(doc), "message": "Return request submitted successfully"},
    )


@app.get("/api/admin/dashboard")
async def admin_dashboard(request: Request, session: SessionDep) -> JSONResponse:
    user_doc, err = await _get_authenticated_user(request, session)
    if err:
        return err
    admin_err = _require_admin(user_doc)
    if admin_err:
        return admin_err

    total_products = int((await session.scalar(select(func.count()).select_from(Product))) or 0)
    total_orders = int((await session.scalar(select(func.count()).select_from(Order))) or 0)
    total_customers = int((await session.scalar(select(func.count()).select_from(User).where(User.role == "customer"))) or 0)

    total_revenue = float(
        (await session.scalar(select(func.coalesce(func.sum(Order.total), 0)).where(Order.status == "delivered"))) or 0
    )

    recent_res = await session.execute(select(Order).order_by(desc(Order.created_at)).limit(10))
    recent_rows = recent_res.scalars().all()
    recent_orders = [order_orm_to_api_dict(o) for o in recent_rows]

    del_ord_res = await session.execute(select(Order).where(Order.status == "delivered"))
    delivered_orders = del_ord_res.scalars().all()

    product_qty: Dict[int, int] = defaultdict(int)
    for o in delivered_orders:
        for item in json.loads(o.items_json or "[]"):
            pid = item.get("product")
            q = int(item.get("quantity") or 0)
            iid = safe_int_id(pid) if not isinstance(pid, int) else pid
            if iid is not None:
                product_qty[iid] += q

    top_ids = sorted(product_qty.keys(), key=lambda k: product_qty[k], reverse=True)[:5]
    top_products_docs: List[Dict[str, Any]] = []
    if top_ids:
        pr = await session.execute(select(Product).where(Product.id.in_(top_ids)))
        pmap = {p.id: p for p in pr.scalars().all()}
        for tid in top_ids:
            p = pmap.get(tid)
            if p:
                d = product_orm_to_api_dict(p)
                top_products_docs.append({"_id": d["_id"], "name": d["name"], "price": d["price"], "images": d["images"]})

    six_months_ago = datetime.now(timezone.utc) - timedelta(days=30 * 6)
    monthly_by_key: Dict[Tuple[int, int], Dict[str, Any]] = defaultdict(lambda: {"totalSales": 0.0, "orderCount": 0})
    mo_res = await session.execute(
        select(Order).where(Order.status == "delivered", Order.created_at >= six_months_ago)
    )
    for o in mo_res.scalars().all():
        ca = o.created_at
        if ca.tzinfo is None:
            ca = ca.replace(tzinfo=timezone.utc)
        key = (ca.year, ca.month)
        monthly_by_key[key]["totalSales"] += float(o.total)
        monthly_by_key[key]["orderCount"] += 1

    monthly_sales = [
        {"_id": {"year": y, "month": m}, "totalSales": v["totalSales"], "orderCount": v["orderCount"]}
        for (y, m), v in sorted(monthly_by_key.items())
    ]

    st_res = await session.execute(select(Order.status, func.count(Order.id)).group_by(Order.status))
    status_breakdown = [{"_id": s, "count": c} for s, c in st_res.all()]

    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "data": {
                "overview": {
                    "totalProducts": total_products,
                    "totalOrders": total_orders,
                    "totalCustomers": total_customers,
                    "totalRevenue": total_revenue,
                },
                "recentOrders": serialize_document(recent_orders),
                "topProducts": serialize_document(top_products_docs),
                "monthlySales": serialize_document(monthly_sales),
                "statusBreakdown": serialize_document(status_breakdown),
            },
        },
    )




@app.get("/api/admin/orders")
async def admin_orders(request: Request, session: SessionDep) -> JSONResponse:
    user_doc, err = await _get_authenticated_user(request, session)
    if err:
        return err
    admin_err = _require_admin(user_doc)
    if admin_err:
        return admin_err

    q = request.query_params
    page = int(q.get("page") or 1)
    limit = int(q.get("limit") or 10)
    status = q.get("status")
    search = q.get("search")

    conds: List[Any] = []
    if status:
        conds.append(Order.status == status)
    if search:
        term = f"%{search}%"
        conds.append(or_(Order.order_id.ilike(term), Order.shipping_json.ilike(term)))

    where_expr = and_(*conds) if conds else True  # type: ignore[arg-type]
    total = int((await session.execute(select(func.count()).select_from(Order).where(where_expr))).scalar_one() or 0)
    skip = (page - 1) * limit

    res = await session.execute(
        select(Order).where(where_expr).order_by(desc(Order.created_at)).offset(skip).limit(limit)
    )
    rows = res.scalars().all()

    customer_ids = list({o.customer_id for o in rows if o.customer_id is not None})
    customers_by_id: Dict[str, Dict[str, Any]] = {}
    if customer_ids:
        cr = await session.execute(select(User).where(User.id.in_(customer_ids)))
        for c in cr.scalars().all():
            customers_by_id[str(c.id)] = public_user_profile(user_orm_to_api_dict(c))

    out_docs: List[Dict[str, Any]] = []
    for o in rows:
        d = order_orm_to_api_dict(o)
        cid = o.customer_id
        if cid is not None and str(cid) in customers_by_id:
            d["customer"] = customers_by_id[str(cid)]
        out_docs.append(d)

    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "data": {
                "orders": serialize_document(out_docs),
                "pagination": {
                    "current": page,
                    "pages": int(math.ceil(total / float(limit))) if limit else 1,
                    "total": total,
                },
            },
        },
    )


@app.get("/api/admin/products")
async def admin_products(request: Request, session: SessionDep) -> JSONResponse:
    user_doc, err = await _get_authenticated_user(request, session)
    if err:
        return err
    admin_err = _require_admin(user_doc)
    if admin_err:
        return admin_err

    q = request.query_params
    page = int(q.get("page") or 1)
    limit = int(q.get("limit") or 10)
    category = q.get("category")
    search = q.get("search")

    conds: List[Any] = []
    if category:
        conds.append(Product.category == category)
    if search:
        term = f"%{search}%"
        conds.append(or_(Product.name.ilike(term), Product.description.ilike(term)))

    where_expr = and_(*conds) if conds else True  # type: ignore[arg-type]
    total = int((await session.execute(select(func.count()).select_from(Product).where(where_expr))).scalar_one() or 0)
    skip = (page - 1) * limit

    res = await session.execute(
        select(Product).where(where_expr).order_by(desc(Product.created_at)).offset(skip).limit(limit)
    )
    docs = [product_orm_to_api_dict(p) for p in res.scalars().all()]

    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "data": {
                "products": serialize_document(docs),
                "pagination": {
                    "current": page,
                    "pages": int(math.ceil(total / float(limit))) if limit else 1,
                    "total": total,
                },
            },
        },
    )


@app.get("/api/admin/customers")
async def admin_customers(request: Request, session: SessionDep) -> JSONResponse:
    user_doc, err = await _get_authenticated_user(request, session)
    if err:
        return err
    admin_err = _require_admin(user_doc)
    if admin_err:
        return admin_err

    q = request.query_params
    page = int(q.get("page") or 1)
    limit = int(q.get("limit") or 10)
    search = q.get("search")

    conds: List[Any] = [User.role == "customer"]
    if search:
        term = f"%{search}%"
        conds.append(
            or_(
                User.first_name.ilike(term),
                User.last_name.ilike(term),
                User.email.ilike(term),
                User.phone.ilike(term),
            )
        )

    where_expr = and_(*conds)
    total = int((await session.execute(select(func.count()).select_from(User).where(where_expr))).scalar_one() or 0)
    skip = (page - 1) * limit

    res = await session.execute(select(User).where(where_expr).order_by(desc(User.created_at)).offset(skip).limit(limit))
    docs = [public_user_profile(user_orm_to_api_dict(u)) for u in res.scalars().all()]

    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "data": {
                "customers": serialize_document(docs),
                "pagination": {
                    "current": page,
                    "pages": int(math.ceil(total / float(limit))) if limit else 1,
                    "total": total,
                },
            },
        },
    )


@app.get("/api/orders/admin/all")
async def orders_admin_all(request: Request, session: SessionDep) -> JSONResponse:
    q = request.query_params
    page = int(q.get("page") or 1)
    limit = int(q.get("limit") or 10)
    status = q.get("status")
    search = q.get("search")

    conds: List[Any] = []
    if status:
        conds.append(Order.status == status)
    if search:
        term = f"%{search}%"
        conds.append(or_(Order.order_id.ilike(term), Order.shipping_json.ilike(term)))

    where_expr = and_(*conds) if conds else True  # type: ignore[arg-type]
    total = int((await session.execute(select(func.count()).select_from(Order).where(where_expr))).scalar_one() or 0)
    skip = (page - 1) * limit

    res = await session.execute(
        select(Order).where(where_expr).order_by(desc(Order.created_at)).offset(skip).limit(limit)
    )
    docs = [order_orm_to_api_dict(o) for o in res.scalars().all()]

    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "data": {
                "orders": serialize_document(docs),
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total,
                    "pages": int(math.ceil(total / float(limit))) if limit else 1,
                },
            },
        },
    )


# --- Production UI (Vite build output: frontend `npm run build` → backend/frontend_dist) ---
_frontend_dist = _BACKEND_ROOT / "frontend_dist"
if _frontend_dist.is_dir():
    app.mount(
        "/",
        StaticFiles(directory=str(_frontend_dist), html=True),
        name="spa",
    )
