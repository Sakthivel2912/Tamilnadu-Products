from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    first_name: Mapped[str] = mapped_column(String(100))
    last_name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    phone: Mapped[str] = mapped_column(String(20))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="customer")
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_google_user: Mapped[bool] = mapped_column(Boolean, default=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    phone_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    address_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    login_count: Mapped[int] = mapped_column(Integer, default=0)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Product(Base):
    __tablename__ = "products"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(500))
    slug: Mapped[str] = mapped_column(String(500), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    short_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(100))
    price: Mapped[float] = mapped_column(Float, default=0)
    original_price: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    images_json: Mapped[str] = mapped_column(Text, default="[]")
    sizes_json: Mapped[str] = mapped_column(Text, default="[]")
    colors_json: Mapped[str] = mapped_column(Text, default="[]")
    stock: Mapped[int] = mapped_column(Integer, default=0)
    size_stock_json: Mapped[str] = mapped_column(Text, default="{}")
    rating: Mapped[float] = mapped_column(Float, default=0)
    reviews: Mapped[int] = mapped_column(Integer, default=0)
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    featured: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    seo_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    specifications_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Order(Base):
    __tablename__ = "orders"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    order_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    customer_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    items_json: Mapped[str] = mapped_column(Text, default="[]")
    shipping_json: Mapped[str] = mapped_column(Text, default="{}")
    subtotal: Mapped[float] = mapped_column(Float, default=0)
    total: Mapped[float] = mapped_column(Float, default=0)
    status: Mapped[str] = mapped_column(String(40), default="pending")
    payment_status: Mapped[str] = mapped_column(String(40), default="pending")
    payment_method: Mapped[str] = mapped_column(String(40), default="cod")
    payment_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    razorpay_order_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    razorpay_payment_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    razorpay_signature: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    tracking_number: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    estimated_delivery: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    actual_delivery: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status_history_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Contact(Base):
    __tablename__ = "contacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str] = mapped_column(String(255))
    phone: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    subject: Mapped[str] = mapped_column(String(300))
    message: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(50), default="general")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ReturnRequest(Base):
    __tablename__ = "return_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    return_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    order_pk: Mapped[Optional[int]] = mapped_column(ForeignKey("orders.id"), nullable=True)
    customer_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    items_json: Mapped[str] = mapped_column(Text, default="[]")
    reason: Mapped[str] = mapped_column(String(80))
    condition: Mapped[str] = mapped_column(String(40), default="new")
    images_json: Mapped[str] = mapped_column(Text, default="[]")
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="pending")
    refund_method: Mapped[str] = mapped_column(String(40), default="original")
    status_history_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
