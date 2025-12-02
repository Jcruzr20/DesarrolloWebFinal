# models.py
from sqlalchemy import Column, String, DateTime, DECIMAL, Integer, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.mysql import CHAR
from datetime import datetime
from uuid import uuid4

from database import Base


# -------------------------
# CUSTOMER
# -------------------------
class Customer(Base):
    __tablename__ = "customer"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name = Column(String(100))
    email = Column(String(100), unique=True, nullable=False)
    phone = Column(String(30))
    hashed_password = Column(String(255), nullable=False)

    # Campo de verificación de correo
    email_verified = Column(Boolean, default=False)

    # Campo de puntos reales del cliente
    points = Column(Integer, nullable=False, default=0)

    # Relación con pedidos
    orders = relationship("Order", back_populates="customer")


# -------------------------
# ORDER
# -------------------------
class Order(Base):
    __tablename__ = "orders"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id = Column(String(36), ForeignKey("customer.id"))
    total = Column(DECIMAL(10, 2))
    created_at = Column(DateTime, default=datetime.now)

    # NUEVO: estado del pedido
    status = Column(String(50), nullable=False, default="En preparación")

    # Relaciones
    customer = relationship("Customer", back_populates="orders")
    items = relationship("OrderItem", back_populates="order")
    tracking = relationship("Tracking", back_populates="order", uselist=False)



# -------------------------
# ORDER ITEM
# -------------------------
class OrderItem(Base):
    __tablename__ = "order_item"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    order_id = Column(String(36), ForeignKey("orders.id"))
    product_name = Column(String(100))
    quantity = Column(Integer)
    price = Column(DECIMAL(10, 2))

    # Relación con pedido
    order = relationship("Order", back_populates="items")


# -------------------------
# TRACKING
# -------------------------
class Tracking(Base):
    __tablename__ = "tracking"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    order_id = Column(String(36), ForeignKey("orders.id"))
    status = Column(String(50))
    updated_at = Column(DateTime, default=datetime.now)

    # Coincide con tu columna en MySQL
    driver_id = Column(String(36), ForeignKey("delivery_person.id"), nullable=True)

    # Relaciones
    order = relationship("Order", back_populates="tracking")
    driver = relationship("DeliveryPerson", back_populates="deliveries")


# -------------------------
# DELIVERY PERSON
# -------------------------
class DeliveryPerson(Base):
    __tablename__ = "delivery_person"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name = Column(String(100))
    phone = Column(String(30))

    # Relación inversa: trackings que tiene asignados
    deliveries = relationship("Tracking", back_populates="driver")


# -------------------------
# PRODUCTOS
# -------------------------
class ProductORM(Base):
    __tablename__ = "products"

    id = Column(CHAR(36), primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    price = Column(DECIMAL(10, 2), nullable=False)
    description = Column(String(255), nullable=True)
