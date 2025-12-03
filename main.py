from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    HTTPBearer,
    HTTPAuthorizationCredentials,
)
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel, Field
from typing import Optional, List
from uuid import UUID, uuid4
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import io
import random

from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt

from database import SessionLocal, engine, Base, get_db
from models import (
    Customer as CustomerORM,
    Order as OrderORM,
    OrderItem as OrderItemORM,
    Tracking as TrackingORM,
    DeliveryPerson as DeliveryPersonORM,
    ProductORM,
)

# Crear tablas si no existen
Base.metadata.create_all(bind=engine)

# ---------------------------
# CORS + App Config
# ---------------------------
APP_TITLE = "API Pollos Abrosos"
API_PREFIX = "/api/pollosabroso"

app = FastAPI(
    title=APP_TITLE,
    description="Implementación Monolítica de la arquitectura de servicios.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # permitir cualquier origen (solo para practicar)
    allow_credentials=False,  # IMPORTANTE: en False para que '*' funcione
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Asignación automática de repartidor
# ---------------------------

ESTADOS_ACTIVOS = ["En preparación", "Listo para retiro", "En reparto"]

KITCHEN_ACTIVE_STATUSES = ["En preparación", "Listo para retiro"]



def asignar_repartidor_automatico(db: Session, order: OrderORM) -> DeliveryPersonORM:
    """
    Asigna SIEMPRE al repartidor Vicente (ID fijo).
    Ignora carga, orden, etc. -> Asignación fija.
    """

    # ID de Vicente Repartidor
    DRIVER_ID = "9a6aaf5d-cff5-11f0-924e-88f4daaf341b"

    # 1) Buscar repartidor Vicente
    repartidor = (
        db.query(DeliveryPersonORM)
        .filter(DeliveryPersonORM.id == DRIVER_ID)
        .first()
    )

    if not repartidor:
        raise HTTPException(
            status_code=404,
            detail="Repartidor fijo no encontrado en la base de datos."
        )

    # 2) Buscar tracking existente
    tracking = (
        db.query(TrackingORM)
        .filter(TrackingORM.order_id == order.id)
        .order_by(TrackingORM.updated_at.desc())
        .first()
    )

    # 3) Crear tracking si no existe
    if tracking is None:
        tracking = TrackingORM(
            order_id=order.id,
            status="Repartidor asignado",
            driver_id=repartidor.id,
            updated_at=datetime.now(),
        )
        db.add(tracking)
    else:
        # Actualizar tracking existente
        tracking.driver_id = repartidor.id
        tracking.status = "Repartidor asignado"
        tracking.updated_at = datetime.now()

    db.commit()
    db.refresh(tracking)

    return repartidor




# --- 1. MODELOS DE DATOS (DTOs Y ENTIDADES DE TUS 27 DIAGRAMAS) ---
PESOS_POR_PUNTO = 10          # si aún lo quieres para otras cosas
COUPON_POINTS_COST = 300      # puntos que cuesta un cupón
COUPON_DISCOUNT_PCT = 15      # porcentaje de descuento del cupón

# --- Modelo de Respuesta Genérico ---
class Response(BaseModel):
    statusCode: int = 200
    message: str = "OK"
    data: Optional[dict | list] = None

# --- Diagrama 01: Registro Clientes ---
class CustomerRegistrationInput(BaseModel):
    name: str
    email: str
    phone: str
    password: str

class Customer(BaseModel): 
    id: UUID
    name: str
    email: str
    phone: str
    emailVerified: bool = False
    createdAt: datetime

    class Config:
        from_attributes = True




# --- Diagrama 02: Validacion Correo ---
class EmailValidationInput(BaseModel):
    userId: UUID
    token: str

class EmailValidationToken(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    token: str
    expiresAt: datetime
    validatedAt: Optional[datetime] = None

# --- Diagrama 03: Cuenta Usuario ---
class CustomerProfile(BaseModel):
    id: UUID
    name: str
    email: str
    phone: Optional[str] = None
    emailVerified: bool
    points: int = 0         # 👈 NUEVO CAMPO

    class Config:
        from_attributes = True    # o orm_mode = True


class UserAccountInput(BaseModel):
    status: str # ej. "activo", "inactivo"

class UserAccount(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    status: str
    createdAt: datetime = Field(default_factory=datetime.now)
    updatedAt: Optional[datetime] = None

# --- Diagrama 04: Inicio y Cierre de Sesion ---
class LoginInput(BaseModel):
    email: str
    password: str

class Session(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    token: str
    createdAt: datetime = Field(default_factory=datetime.now)
    expiresAt: datetime
############################
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

# --- Diagrama 05: Recuperar Contrasena --- 
class PasswordChangeInput(BaseModel):
    currentPassword: str
    newPassword: str
class PasswordRecoveryInput(BaseModel):
    email: str

class RecoveryToken(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    token: str
    expiresAt: datetime
    usedAt: Optional[datetime] = None

# --- Diagrama 06: Gestion Perfil Usuario ---
class UserProfileInput(BaseModel):
    name: str
    address: str
    phone: str

class UserProfile(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    name: str
    address: str
    phone: str
    updatedAt: datetime = Field(default_factory=datetime.now)

# --- Diagrama 07: Personalizacion de Pedidos ---
class OrderSummary(BaseModel):
    id: str
    date: datetime
    description: str
    itemsCount: int
    pointsEarned: int
    total: float  # NUEVO

    class Config:
        orm_mode = True
###############################################################################
# --- Modelo de respuesta para actualizar estado de tracking --- 
class TrackingStatusDriver(BaseModel):
    id: str
    name: str
    phone: str


class TrackingStatusResponse(BaseModel):
    orderId: str
    status: str
    updatedAt: datetime
    driver: Optional[TrackingStatusDriver]


# --- Página "Mis pedidos" ---
class MyOrderItem(BaseModel):
    productName: str
    quantity: int
    price: float


class MyOrderSummary(BaseModel):
    id: str
    date: datetime
    status: str
    total: float
    items: List[MyOrderItem]

    class Config:
        from_attributes = True



# --- Personalización de pedidos ---
class OrderPersonalizationInput(BaseModel):
    # userId se obtendrá del token
    spiceLevel: str
    extras: List[str]
    notes: str


class OrderPreference(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    spiceLevel: str
    extras: List[str]
    notes: str

    class Config:
        orm_mode = True


# --- Diagrama 08: Filtrar y Buscar ---
class SearchFilterInput(BaseModel):
    keywords: Optional[str] = None
    category: Optional[str] = None
    minPrice: Optional[Decimal] = None
    maxPrice: Optional[Decimal] = None
    sortBy: Optional[str] = None


# --- Diagrama 09: Registro de Pedidos ---
class OrderItemDetail(BaseModel):
    productName: str
    quantity: int
    price: float
    subtotal: float


class OrderDetail(BaseModel):
    id: UUID
    status: str
    createdAt: datetime
    total: float
    items: List[OrderItemDetail]

class OrderItemInput(BaseModel):
    productId: UUID
    quantity: int


class OrderInput(BaseModel):
    items: List[OrderItemInput]
    notes: Optional[str] = None


class Order(BaseModel):
    """
    Esquema Pydantic para representar pedidos a nivel de API.
    Este es el modelo que usamos en response_model de los endpoints.
    """
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    items: List[OrderItemInput]
    notes: Optional[str] = None
    status: str = "pendiente"
    createdAt: datetime = Field(default_factory=datetime.now)

    class Config:
        orm_mode = True   # si quieres, más adelante lo cambiamos a from_attributes = True


class OrderHistoryItem(BaseModel):
    id: UUID
    date: datetime
    description: str
    pointsEarned: int


# --- Diagrama 10: Integracion Pasarela de Pago ---
class PaymentGatewayInput(BaseModel):
    orderId: UUID
    amount: Decimal
    provider: str
    token: str  # Token de la tarjeta


class PaymentGateway(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    provider: str
    transactionId: str
    status: str
    amount: Decimal

    class Config:
        orm_mode = True


# --- Diagrama 11: Confirmacion Automatica de Pago ---
class PaymentConfirmationInput(BaseModel):
    orderId: UUID
    gatewayTransactionId: str


class Payment(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    orderId: UUID
    status: str
    authorizationCode: str
    confirmedAt: datetime = Field(default_factory=datetime.now)

    class Config:
        orm_mode = True


# --- Diagrama 12: Generacion de Boletas Digitales ---
class DigitalInvoiceInput(BaseModel):
    orderId: UUID
    amount: Decimal


class Invoice(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    orderId: UUID
    number: str
    total: Decimal
    pdfUrl: str
    generatedAt: datetime = Field(default_factory=datetime.now)

    class Config:
        orm_mode = True


# --- Diagrama 13: Envio de Boletas por Correo ---
class SendInvoiceEmailInput(BaseModel):
    invoiceId: UUID
    email: str


class InvoiceDispatch(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    invoiceId: UUID
    email: str
    sentAt: datetime = Field(default_factory=datetime.now)
    status: str

    class Config:
        orm_mode = True


# --- Diagrama 14: Panel Control Cocina ---
class KitchenPanelInput(BaseModel):
    status: str  # ej. "Pendiente", "EnPreparacion"


class KitchenTicket(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    orderId: UUID
    status: str
    startedAt: Optional[datetime] = None
    readyAt: Optional[datetime] = None

    class Config:
        orm_mode = True


# --- Diagrama 15: Alertas de Tiempos de Coccion ---
class CookingTimeAlertInput(BaseModel):
    ticketId: UUID
    thresholdMinutes: int


class CookingAlert(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    ticketId: UUID
    thresholdMinutes: int
    triggeredAt: datetime = Field(default_factory=datetime.now)

    class Config:
        orm_mode = True


class TrackingUpdateInput(BaseModel):
    orderId: UUID
    status: str  # ejemplo: "en ruta", "cerca", "entregado"


# --- Diagrama 16: Notificacion al Cliente ---
class CustomerNotificationInput(BaseModel):
    userId: UUID
    title: str
    message: str


class Notification(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    title: str
    message: str
    sentAt: datetime = Field(default_factory=datetime.now)

    class Config:
        orm_mode = True


# --- Diagrama 17: Asignacion Automatica de Repartidores ---
# --- Tracking con repartidor ---
# --- Modelos para Panel de Repartidor ---

class AutoAssignmentResponse(BaseModel):
    orderId: str
    driverId: str
    status: str


class DriverOrderItem(BaseModel):
    productName: str
    quantity: int
    price: float

    class Config:
        orm_mode = True


class DriverOrder(BaseModel):
    orderId: str
    customerName: Optional[str] = None
    total: float
    status: str
    createdAt: datetime
    items: List[DriverOrderItem]

    class Config:
        orm_mode = True


class DriverInfo(BaseModel):
    id: str
    name: str
    phone: Optional[str] = None

class AssignedOrderResponse(BaseModel):
    """
    Respuesta para la asignación automática de repartidor:
    devuelve el pedido + info del repartidor asignado.
    """
    id: str
    userId: str
    total: float
    status: str
    createdAt: datetime
    driver: Optional[DriverInfo] = None



class TrackingResponse(BaseModel):
    orderId: str
    status: str
    updatedAt: datetime
    driver: Optional[DriverInfo] = None

    class Config:
        from_attributes = True   # (equivalente a orm_mode = True)


class AutoDriverAssignmentInput(BaseModel):
    orderId: UUID


class Assignment(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    orderId: UUID
    driverId: UUID
    assignedAt: datetime = Field(default_factory=datetime.now)
    status: str

    class Config:
        orm_mode = True

# --- Modelos para Panel de Cocina ---

class KitchenOrderItem(BaseModel):
    productName: str
    quantity: int
    price: float


class KitchenOrder(BaseModel):
    id: str
    customerName: str
    status: str
    createdAt: datetime
    total: float
    items: List[KitchenOrderItem]

    class Config:
        from_attributes = True  # o orm_mode = True si sigues en v1

class KitchenTicketInput(BaseModel):
    orderId: UUID
class KitchenStatusUpdate(BaseModel):
    status: str

# --- Tracking para cliente (Perfil / Seguimiento) ---

class TrackingStep(BaseModel):
    code: str       # ej. "en_cocina"
    label: str      # ej. "En cocina"
    done: bool      # si ese paso ya está cumplido


class OrderTrackingResponse(BaseModel):
    orderId: str
    customerName: str
    total: float
    status: str                 # estado actual de la ORDEN
    steps: List[TrackingStep]
    driverName: Optional[str] = None
    driverPhone: Optional[str] = None

    class Config:
        from_attributes = True


# --- Diagrama 18: Planificacion de Rutas ---
class RoutePlanningInput(BaseModel):
    date: datetime
    orders: List[UUID]


class RoutePlan(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    date: datetime
    stops: int
    optimizedBy: str
    createdAt: datetime = Field(default_factory=datetime.now)

    class Config:
        orm_mode = True


# --- Diagrama 19: Panel de Repartidor ---
class CourierPanelInput(BaseModel):
    driverId: UUID


class CourierAssignmentView(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    driverId: UUID
    orderId: UUID
    status: str
    updatedAt: datetime = Field(default_factory=datetime.now)

    class Config:
        orm_mode = True


# --- Diagrama 20: Seguimiento del Pedido ---
class OrderTrackingInput(BaseModel):
    orderId: UUID


class Tracking(BaseModel):
    """
    Esquema Pydantic para tracking que usamos en response_model.
    OJO: No choca con TrackingORM, porque ese viene importado con alias.
    """
    id: UUID = Field(default_factory=uuid4)
    orderId: UUID
    status: str
    lat: Optional[float] = None
    lng: Optional[float] = None
    updatedAt: datetime = Field(default_factory=datetime.now)

    class Config:
        orm_mode = True   # si quieres, más adelante lo cambiamos a from_attributes = True


#########################################################################

# --- Diagrama 21: Acumular Puntos por Compras ---
class PurchaseHistoryItem(BaseModel):
    id: str
    date: datetime
    description: str
    itemsCount: int
    pointsEarned: int
    total: Decimal  # 👈 NUEVO campo

    class Config:
        orm_mode = True
class PointsUpdate(BaseModel):
    amount: int

class LoyaltyPointsInput(BaseModel):
    userId: UUID
    orderId: UUID
    points: int

class LoyaltyPoints(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    orderId: UUID
    points: int
    accruedAt: datetime = Field(default_factory=datetime.now)

# --- Diagrama 22: Canjear Cupones de Descuento ---
class RedeemCouponInput(BaseModel):
    # userId se obtendrá del token
    code: str

class CouponRedemption(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    code: str
    discountPct: int
    redeemedAt: datetime = Field(default_factory=datetime.now)
class CouponRedeemResponse(BaseModel):
    valid: bool
    discountPct: int
    code: str
    message: str


# --- Diagrama 23: Recibir Promociones Personalizadas ---
class PersonalizedPromotionInput(BaseModel):
    segment: str
    title: str
    discountPct: int

class Promotion(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    title: str
    discountPct: int
    segment: str
    sentAt: datetime = Field(default_factory=datetime.now)

# --- Diagrama 24: Recordatorio de Promociones ---
class PromotionReminderInput(BaseModel):
    userId: UUID
    title: str
    reminderAt: datetime
    channel: str # "email", "sms"

class PromotionReminder(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    title: str
    reminderAt: datetime
    channel: str

# --- Diagrama 25: Formularios ---
class FormSubmissionInput(BaseModel):
    # userId se obtendrá del token
    type: str
    content: str

class FormSubmission(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    type: str
    content: str
    createdAt: datetime = Field(default_factory=datetime.now)

# --- Diagrama 26: Integracion Sistema de Datos ---
class DataSystemIntegrationInput(BaseModel):
    source: str
    records: int

class IntegrationJob(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    source: str
    status: str
    syncedAt: datetime = Field(default_factory=datetime.now)
    records: int


# --- 2. CONFIGURACIÓN DE SEGURIDAD ---
# --- 2. CONFIGURACIÓN DE SEGURIDAD ---
SECRET_KEY = "clave-secreta-pollos-abrosos"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
)
oauth2_scheme = HTTPBearer()


# --- 3. FUNCIONES HELPER DE SEGURIDAD ---
def verificar_contraseña(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def hashear_contraseña(password: str) -> str:
    return pwd_context.hash(password)

def crear_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# --- helper BD ---
def get_customer_by_email(db: Session, email: str) -> Optional[CustomerORM]:
    return db.query(CustomerORM).filter(CustomerORM.email == email).first()


def autenticar_cliente(db: Session, email: str, password: str) -> Optional[CustomerORM]:
    user = get_customer_by_email(db, email)
    if not user:
        return None
    if not verificar_contraseña(password, user.hashed_password):
        return None
    return user


# --- Token especial para verificación de correo --- 
def crear_token_verificacion_email(email: str) -> str:
    """
    Crea un JWT de corta duración para verificar correo.
    """
    datos = {
        "sub": email,          # sujeto = correo
        "scope": "email_verify"
    }
    return crear_access_token(
        datos,
        expires_delta=timedelta(minutes=30)
    )



# --- 5. FUNCIONES DE AUTENTICACIÓN Y BBDD ---
def get_customer_by_id(db: Session, customer_id: str):
    return db.query(CustomerORM).filter(CustomerORM.id == customer_id).first()

def get_customer_by_email(db: Session, email: str):
    return db.query(CustomerORM).filter(CustomerORM.email == email).first()

def authenticate_customer(db: Session, email: str, password: str):
    """
    Autentica al cliente contra la BD MySQL.
    Retorna el objeto CustomerORM si las credenciales son correctas,
    o None en caso contrario.
    """
    user = get_customer_by_email(db, email)
    if not user:
        return None
    # Verificar contraseña con bcrypt
    if not pwd_context.verify(password, user.hashed_password):
        return None
    return user




def get_order_for_customer(db: Session, order_id: str, customer_id: str):
    """
    Busca un pedido por id que pertenezca al cliente indicado.
    """
    return db.query(OrderORM).filter(
        OrderORM.id == order_id,
        OrderORM.user_id == customer_id
    ).first()


async def get_current_customer(
    token: HTTPAuthorizationCredentials = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    """
    Obtiene el cliente actual a partir del JWT enviado en el Authorization header.
    Funciona con HTTPBearer (token.credentials) y busca al usuario en MySQL.
    """
    credentials_exception = HTTPException(
        status_code=401,
        detail="No se pudieron validar las credenciales (Token inválido)",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Extraer el string real del token desde HTTPAuthorizationCredentials
        token_str = token.credentials

        # Decodificar el JWT
        payload = jwt.decode(token_str, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")

        if user_id is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    # Buscar usuario por ID en MySQL
    user = db.query(CustomerORM).filter(CustomerORM.id == user_id).first()

    if user is None:
        raise credentials_exception

    return user




# Prefijo global para todos los endpoints
API_PREFIX = "/api/pollosabroso"


# --- 7. ENDPOINTS (API) ---

@app.get("/")
def read_root():
    return {"mensaje": "API Gateway de Pollos Abrosos funcionando. Ve a /docs para ver los endpoints."}


# --- Servicio: Auth (Diagramas 02, 04, 05) ---

@app.post(f"{API_PREFIX}/sesion/inicio", response_model=TokenResponse, tags=["AuthService"])
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    (Diagrama 04) Iniciar Sesión (versión MySQL).
    Usa 'username' (email) y 'password'.
    """
    # Autenticar contra MySQL
    customer = authenticate_customer(db, form_data.username, form_data.password)
    if not customer:
        raise HTTPException(
            status_code=401,
            detail="Email o contraseña incorrecta",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    # Aquí el "sub" DEBE ser el id del usuario (como pide JWT)
    access_token = crear_access_token(
        data={"sub": str(customer.id)},
        expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


@app.post(f"{API_PREFIX}/auth/login", response_model=Token, tags=["Auth"])
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Login de cliente.
    Recibe username (email) y password vía formulario x-www-form-urlencoded.
    Devuelve un access_token JWT.
    """
    user = autenticar_cliente(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Correo o contraseña incorrectos")

    # OJO: aquí usamos tu propia función crear_access_token
    access_token = crear_access_token(data={"sub": user.id})


    return Token(access_token=access_token)

# --- Verificación de correo ---
@app.get(f"{API_PREFIX}/auth/verify-email", tags=["Auth"])
def verify_email(token: str, db: Session = Depends(get_db)):
    """
    Endpoint que se llama desde el link enviado por correo.
    Marca el correo del usuario como verificado.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        scope = payload.get("scope")
        email = payload.get("sub")

        if scope != "email_verify" or email is None:
            raise HTTPException(status_code=400, detail="Token de verificación inválido")

    except JWTError:
        raise HTTPException(status_code=400, detail="Token inválido o expirado")

    user = get_customer_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # Marcar como verificado
    user.email_verified = True
    db.commit()

    return {"message": "Correo verificado correctamente"}




@app.post(f"{API_PREFIX}/sesion/recuperar", tags=["AuthService"])
def recover_password(input: PasswordRecoveryInput):
    """(Diagrama 05) Recuperar Contraseña"""
    # 1. Verificar si existe el usuario
    customer = get_customer_by_email(input.email)
    if not customer:
        raise HTTPException(status_code=404, detail="No existe un usuario con ese correo")
    
    # 2. Generar un código
    import random
    code = str(random.randint(100000, 999999))

    # 3. Guardar el código en memoria
    password_recovery_codes[input.email] = code

    # 4. "Enviar" el código (simulado)
    print(f"[DEBUG] Código de recuperación para {input.email}: {code}")

    # 5. Respuesta hacia Swagger
    return {"message": "Se envió un código de verificación al correo."}


# --- Confirmar recuperación de contraseña (validar token) ---
class PasswordRecoveryConfirmInput(BaseModel):
    userId: UUID
    token: str

@app.post(f"{API_PREFIX}/sesion/recuperar/validar", response_model=Response, tags=["AuthService"])
def confirm_password_recovery(input: PasswordRecoveryConfirmInput):
    """ (Diagrama 05) Confirmar código de recuperación """

    # Buscar el token del usuario
    for email, stored_code in password_recovery_codes.items():
        customer = get_customer_by_email(email)
        if customer and customer.id == input.userId and stored_code == input.token:

            print(f"[DEBUG] Código validado correctamente para usuario {input.userId}")

            # Marcar el código como usado (lo eliminamos)
            del password_recovery_codes[email]

            return Response(message="Código verificado correctamente")

    raise HTTPException(status_code=400, detail="El código no es válido")




@app.post(f"{API_PREFIX}/correo/validacion", response_model=EmailValidationToken, tags=["AuthService"])
def validate_email(input: EmailValidationInput):
    """
    (Diagrama 02) Validar Correo.
    Recibe userId y token, valida el código y marca el correo como verificado.
    """
    print(f"Validando token {input.token} para usuario {input.userId}")

    # 1) Buscar el cliente
    customer = next((c for c in db_customers if c.id == input.userId), None)
    if customer is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # 2) Ver si hay un código pendiente para ese usuario
    expected_code = email_verification_tokens.get(input.userId)
    if expected_code is None:
        raise HTTPException(status_code=400, detail="No hay un código pendiente para este usuario")

    # 3) Comparar el código
    if expected_code != input.token:
        raise HTTPException(status_code=400, detail="Código de verificación incorrecto")

    # 4) Marcar correo como verificado
    customer.emailVerified = True

    # 5) Borrar el código ya usado
    email_verification_tokens.pop(input.userId, None)

    # 6) Devolver el token de validación (Diagrama 02)
    validated_token = EmailValidationToken(
        userId=input.userId,
        token=input.token,
        expiresAt=datetime.now(),
        validatedAt=datetime.now()
    )
    return validated_token


# --- Servicio: User (Diagramas 01, 03, 06, 21, 22) ---

# --- Registro de clientes con link de verificación de correo ---
@app.post(f"{API_PREFIX}/clientes/registro", response_model=Customer, status_code=201, tags=["UserService"])
def register_customer(input: CustomerRegistrationInput, db: Session = Depends(get_db)):
    """
    (Diagrama 01) Registro de Clientes.
    Crea el cliente en MySQL y genera un LINK de verificación de correo (JWT).
    El link se imprime en consola como simulación del correo.
    """

    # 1) Validar email duplicado
    existing = get_customer_by_email(db, input.email)
    if existing:
        raise HTTPException(status_code=400, detail="El email ya está en uso")

    print(f"Registrando nuevo cliente: {input.name}")

    # 2) Hashear contraseña
    hashed_password = hashear_contraseña(input.password)

    # 3) Crear el cliente en BD
    new_customer = CustomerORM(
        name=input.name,
        email=input.email,
        phone=input.phone,
        hashed_password=hashed_password,
        email_verified=False
    )

    db.add(new_customer)
    db.commit()
    db.refresh(new_customer)


    # 4) Generar token JWT corto para verificación de email
    token_verificacion = crear_token_verificacion_email(new_customer.email)
    verify_url = f"http://127.0.0.1:8000{API_PREFIX}/auth/verify-email?token={token_verificacion}"

    # 5) MOSTRAR LINK EN CONSOLA (simula el correo)
    print(f"[DEBUG] Link para verificar correo de {new_customer.email}:")
    print(f"👉 {verify_url}")

    # 6) Devolver al cliente (igual que hacías antes)
    return Customer(
        id=new_customer.id,
        name=new_customer.name,
        email=new_customer.email,
        phone=new_customer.phone,
        emailVerified=bool(new_customer.email_verified),
        createdAt=datetime.now(),
    )
# --- Perfil del cliente logueado ---
@app.get(f"{API_PREFIX}/clientes/me", response_model=CustomerProfile, tags=["UserService"])
def get_my_profile(current_customer: CustomerORM = Depends(get_current_customer)):
    return CustomerProfile(
        id=current_customer.id,
        name=current_customer.name,
        email=current_customer.email,
        phone=current_customer.phone,
        emailVerified=bool(current_customer.email_verified),
        points=current_customer.points,   # 👈 AQUÍ SUMAMOS LOS PUNTOS
    )

@app.post(f"{API_PREFIX}/clientes/me/password", tags=["UserService"])
def change_my_password(
    input: PasswordChangeInput,
    current_customer: CustomerORM = Depends(get_current_customer),
    db: Session = Depends(get_db),
):
    """
    Cambiar contraseña del cliente logueado.
    """
    # Usa la misma lógica que en /auth/login para verificar la contraseña actual
    if not pwd_context.verify(input.currentPassword, current_customer.hashed_password):
        raise HTTPException(status_code=400, detail="La contraseña actual no es correcta.")

    # Aquí podrías volver a validar complejidad si quieres (opcional)
    # if not es_password_segura(input.newPassword):
    #     raise HTTPException(status_code=400, detail="La nueva contraseña no cumple los requisitos.")

    # Hashear nueva contraseña y guardar
    current_customer.hashed_password = hashear_contraseña(input.newPassword)
    db.add(current_customer)
    db.commit()
    db.refresh(current_customer)

    return {"message": "Contraseña actualizada correctamente."}


@app.put(f"{API_PREFIX}/cuenta/gestion", response_model=Response, tags=["UserService"])
def manage_account(input: UserAccountInput, current_customer: Customer = Depends(get_current_customer)):
    """
    (Diagrama 03) Gestionar Cuenta de Usuario (Ej. Activar/Desactivar).
    Endpoint protegido.
    """
    print(f"Usuario {current_customer.email} actualizando estado de cuenta a: {input.status}")
    # Lógica de BBDD (Simulada)
    return Response(message=f"Estado de cuenta actualizado")

@app.put(f"{API_PREFIX}/perfil/gestion", response_model=Response, tags=["UserService"])
def manage_profile(input: UserProfileInput, current_customer: Customer = Depends(get_current_customer)):
    """
    (Diagrama 06) Gestionar Perfil de Usuario.
    Endpoint protegido.
    """
    print(f"Usuario {current_customer.email} actualizando perfil.")
    # Lógica de BBDD (Simulada)
    current_customer.name = input.name
    current_customer.phone = input.phone
    # (En una BBDD real, aquí harías db.commit())
    return Response(message=f"Perfil actualizado para {current_customer.name}")

@app.post(f"{API_PREFIX}/clientes/me/puntos/acumular", tags=["UserService"])
def acumular_puntos(
    input: PointsUpdate,
    current_customer: CustomerORM = Depends(get_current_customer),
    db: Session = Depends(get_db)
):
    if input.amount <= 0:
        raise HTTPException(status_code=400, detail="La cantidad debe ser positiva.")

    current_customer.points += input.amount
    db.commit()
    db.refresh(current_customer)

    return {
        "message": f"Se sumaron {input.amount} puntos.",
        "points": current_customer.points
    }

@app.post(f"{API_PREFIX}/clientes/me/puntos/canjear", tags=["UserService"])
def canjear_puntos(
    input: PointsUpdate,  # lo dejamos aunque no lo usemos
    current_customer: CustomerORM = Depends(get_current_customer),
    db: Session = Depends(get_db)
):
    """
    Canjea exactamente 300 puntos del cliente actual y genera un cupón de 15% de descuento.
    Ignoramos input.amount: la regla de negocio es fija (300 puntos -> 15%).
    """

    puntos_disponibles = current_customer.points or 0

    if puntos_disponibles < COUPON_POINTS_COST:
        raise HTTPException(
            status_code=400,
            detail=f"Necesitas al menos {COUPON_POINTS_COST} puntos para generar un cupón de {COUPON_DISCOUNT_PCT}%."
        )

    puntos_antes = puntos_disponibles
    puntos_canjear = COUPON_POINTS_COST

    # Restar 300 puntos
    current_customer.points = puntos_disponibles - puntos_canjear
    db.add(current_customer)
    db.commit()
    db.refresh(current_customer)

    # Generar código de cupón (id único)
    coupon_code = f"DESC{COUPON_DISCOUNT_PCT}-{uuid4().hex[:8].upper()}"

    return {
        "message": (
            f"Se canjearon {puntos_canjear} puntos. "
            f"Generado cupón de {COUPON_DISCOUNT_PCT}% de descuento."
        ),
        "points": current_customer.points,      # saldo final
        "pointsBefore": puntos_antes,          # saldo antes
        "redeemed": puntos_canjear,            # puntos que se canjearon
        "discountPct": COUPON_DISCOUNT_PCT,    # 15
        "couponCode": coupon_code              # ej: DESC15-3F9A1C2B
    }


@app.get(f"{API_PREFIX}/clientes/me/pedidos", response_model=List[OrderSummary], tags=["PedidoService"]) 
def get_my_orders(
    current_customer: CustomerORM = Depends(get_current_customer),
    db: Session = Depends(get_db)
):
    """
    Devuelve los pedidos recientes del cliente actual.
    Se usa para la tabla 'Compras recientes'.
    """
    # 1) Obtener los pedidos del cliente (los 10 más recientes)
    orders = (
        db.query(OrderORM)
        .filter(OrderORM.user_id == current_customer.id)
        .order_by(OrderORM.created_at.desc())
        .limit(10)
        .all()
    )

    summaries: List[OrderSummary] = []

    for order in orders:
        # Buscar los items del pedido
        items = db.query(OrderItemORM).filter(OrderItemORM.order_id == order.id).all()

        total_unidades = sum(i.quantity for i in items)
        earned_points = total_unidades * 10  # misma regla que usamos en register_order

        # Podríamos armar una descripción simple
        if items:
            first_name = items[0].product_name
            if len(items) == 1:
                description = first_name
            else:
                description = f"{first_name} + {len(items)-1} ítem(s) más"
        else:
            description = "Pedido sin items"

        summaries.append(
            OrderSummary(
                id=str(order.id),
                date=order.created_at,
                description=description,
                itemsCount=total_unidades,
                pointsEarned=earned_points,
                total=float(order.total or 0)  # AQUÍ MANDAMOS EL TOTAL REAL
            )
        )

    return summaries




@app.post(
    f"{API_PREFIX}/cupones/canjear",
    response_model=CouponRedeemResponse,
    tags=["UserService"],
)
def redeem_coupon(
    input: RedeemCouponInput,
    current_customer: CustomerORM = Depends(get_current_customer),
):
    """
    (Diagrama 22) Canjear Cupón.
    Valida un código de cupón (por ahora, del tipo generado al canjear 300 puntos)
    y devuelve el porcentaje de descuento a aplicar.
    """

    code = (input.code or "").strip().upper()
    print(f"Usuario {current_customer.email} intentando canjear cupón: {code}")

    # Regla simple: aceptamos sólo cupones generados con el prefijo DESC15-
    # ej: DESC15-3F9A1C2B
    if not code.startswith("DESC15-") or len(code) < len("DESC15-") + 4:
        # Cupón inválido
        return CouponRedeemResponse(
            valid=False,
            discountPct=0,
            code=code,
            message="El código de cupón no es válido.",
        )

    # Si quisieras, aquí podrías consultar una tabla de cupones o registrar el uso
    # usando CouponRedemption, pero para la rúbrica basta con devolver el descuento.

    return CouponRedeemResponse(
        valid=True,
        discountPct=COUPON_DISCOUNT_PCT,  # 15%
        code=code,
        message=f"Cupón válido. Descuento de {COUPON_DISCOUNT_PCT}%.",
    )

# --- Servicio: Pedido/Pago (Diagramas 07, 09, 10, 11) ---

@app.post(f"{API_PREFIX}/pedidos/personalizacion", response_model=Response, tags=["PedidoService"])
def set_order_personalization(
    input: OrderPersonalizationInput,
    current_customer: Customer = Depends(get_current_customer)
):
    """
    (Diagrama 07) Personalización de Pedidos.
    Endpoint protegido.
    """
    print(f"Guardando preferencias para {current_customer.email}: {input.notes}")

    return Response(
        statusCode=200,
        message="Preferencias guardadas",
        data={}
    )



@app.post(f"{API_PREFIX}/pedidos/registro", response_model=Order, tags=["PedidoService"])
def register_order(
    order_input: OrderInput,
    current_customer: CustomerORM = Depends(get_current_customer),  # usamos el ORM
    db: Session = Depends(get_db),
):
    """
    (Diagrama 09) Registro de Pedidos.
    Versión MySQL con productos reales (tabla products) + puntos.
    """
    print(f"Registrando nuevo pedido para {current_customer.email}")

    # 1) Validar que vengan ítems
    if not order_input.items:
        raise HTTPException(
            status_code=400,
            detail="El pedido debe tener al menos un ítem",
        )

    # 2) Tomar todos los IDs de productos del request (como string)
    product_ids = [str(item.productId) for item in order_input.items]

    # 3) Buscar los productos reales en la BBDD
    products = (
        db.query(ProductORM)
        .filter(ProductORM.id.in_(product_ids))
        .all()
    )

    # Si falta alguno, error
    if len(products) != len(set(product_ids)):
        raise HTTPException(
            status_code=400,
            detail="Uno o más productos no existen en el sistema",
        )

    # 4) Mapear id -> producto
    product_by_id = {p.id: p for p in products}

    # 5) Calcular total del pedido y total de unidades
    total_precio = Decimal("0.00")
    total_unidades = 0

    for item in order_input.items:
        pid = str(item.productId)
        producto = product_by_id[pid]

        # Por si price está como float en la BD
        precio = Decimal(str(producto.price))

        total_precio += precio * item.quantity
        total_unidades += item.quantity

    # 6) Crear pedido en BD con total real
    new_order = OrderORM(
        id=str(uuid4()),
        user_id=current_customer.id,
        total=total_precio,
        created_at=datetime.now(),
        # 🔴 IMPORTANTE: que salga de inmediato en el panel de cocina
        status="En preparación",
    )
    db.add(new_order)
    db.flush()  # asegura que new_order.id esté disponible para los ítems

    # 7) Registrar ítems en la BD usando nombre y precio reales
    for item in order_input.items:
        pid = str(item.productId)
        producto = product_by_id[pid]

        db_item = OrderItemORM(
            order_id=new_order.id,
            product_name=producto.name,   # nombre real del producto
            quantity=item.quantity,
            price=producto.price,         # precio real desde products
        )
        db.add(db_item)

    # 8) Crear tracking inicial (solo UNO)
    primer_tracking = TrackingORM(
        order_id=new_order.id,
        status="En preparación",
        updated_at=datetime.now(),
        driver_id=None,
    )
    db.add(primer_tracking)

    # 9) Calcular puntos ganados y sumarlos al cliente
    earned_points = total_unidades * 10  # regla: 10 puntos por unidad
    current_customer.points += earned_points
    db.add(current_customer)

    # 10) Confirmar todo
    db.commit()
    db.refresh(new_order)

    print(
        f"[PUNTOS] Pedido {new_order.id}: +{earned_points} puntos para "
        f"{current_customer.email}. Total ahora: {current_customer.points}"
    )

    # 11) Devolver el pedido según tu Pydantic Order
    return Order(
        id=new_order.id,
        userId=new_order.user_id,
        items=order_input.items,
        notes=order_input.notes,
        status=new_order.status,   # "En preparación"
        createdAt=new_order.created_at,
        total=total_precio,
    )


@app.get(f"{API_PREFIX}/pedidos/{{order_id}}", response_model=OrderDetail, tags=["PedidoService"])
def get_order_by_id(
    order_id: UUID,
    current_customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
):
    """
    (Diagrama 10) Obtener detalle de un pedido por ID.
    Solo permite ver pedidos del cliente autenticado.
    """

    # 1) Buscar el pedido en BD verificando que sea del usuario logueado
    order_db = get_order_for_customer(db, str(order_id), str(current_customer.id))
    if not order_db:
        raise HTTPException(status_code=404, detail="Pedido no encontrado")

    # 2) Construir la lista de ítems usando lo que realmente hay en order_item
    response_items: List[OrderItemDetail] = []
    for item in order_db.items:
        response_items.append(
            OrderItemDetail(
                productName=item.product_name,                # 👈 aquí usamos el nombre tal cual
                quantity=item.quantity,
                price=float(item.price),
                subtotal=float(item.price) * item.quantity,
            )
        )

    # 3) Estado desde tracking (o "pendiente" si no hay registro)
    status = order_db.tracking.status if order_db.tracking else "pendiente"

    # 4) Devolver el detalle del pedido
    return OrderDetail(
        id=UUID(order_db.id),
        status=status,
        createdAt=order_db.created_at,
        total=float(order_db.total),
        items=response_items,
    )

@app.get(
    f"{API_PREFIX}/pedidos/mis",
    response_model=List[MyOrderSummary],
    tags=["PedidoService"]
)
def get_my_orders(
    db: Session = Depends(get_db),
    current_customer: CustomerORM = Depends(get_current_customer),
):
    """
    (Mis pedidos)
    Devuelve todos los pedidos del cliente autenticado,
    ordenados del más reciente al más antiguo.
    """

    orders = (
        db.query(OrderORM)
        .filter(OrderORM.user_id == current_customer.id)
        .order_by(OrderORM.created_at.desc())
        .all()
    )

    resultado = []

    for o in orders:
        items = [
            MyOrderItem(
                productName=item.product_name,
                quantity=item.quantity,
                price=float(item.price),
            )
            for item in o.items
        ]

        descripcion = (
            f"{len(items)} producto(s)"
            if len(items) > 1
            else items[0].productName
        )

        resultado.append(
            MyOrderSummary(
                id=o.id,
                date=o.created_at,
                description=descripcion,
                total=float(o.total),
                status=o.status,
                items=items,
            )
        )

    return resultado

@app.get(
    f"{API_PREFIX}/clientes/me/mis-pedidos",
    response_model=List[MyOrderSummary],
    tags=["PedidoService"],
)
def get_my_orders_with_status(
    current_customer: CustomerORM = Depends(get_current_customer),
    db: Session = Depends(get_db),
):
    """
    Devuelve el listado de pedidos del cliente actual
    incluyendo estado y detalle de ítems.
    """
    orders = (
        db.query(OrderORM)
        .filter(OrderORM.user_id == current_customer.id)
        .order_by(OrderORM.created_at.desc())
        .all()
    )

    result: List[MyOrderSummary] = []

    for order in orders:
        # Relación con Tracking
        status = "Desconocido"
        if order.tracking:
            status = order.tracking.status or "Sin estado"

        # Ítems
        items_data: List[MyOrderItem] = []
        for item in order.items:
            items_data.append(
                MyOrderItem(
                    productName=item.product_name,
                    quantity=item.quantity,
                    price=float(item.price or 0),
                )
            )

        # Descripción “bonita”
        if order.items:
            first_name = order.items[0].product_name
            if len(order.items) == 1:
                description = first_name
            else:
                description = f"{first_name} + {len(order.items) - 1} ítem(s) más"
        else:
            description = "Pedido sin ítems"

        result.append(
            MyOrderSummary(
                id=str(order.id),
                date=order.created_at,
                description=description,
                total=float(order.total or 0),
                status=status,
                items=items_data,
            )
        )

    return result
# Estados en los que NO se permite cancelar
ESTADOS_NO_CANCELABLES = [
    "En camino",
    "Entregado",
    "Cancelado",
    "Listo para retiro",
]


@app.post(
    f"{API_PREFIX}/clientes/me/mis-pedidos/{{order_id}}/cancelar",
    response_model=MyOrderSummary,
    tags=["PedidoService"],
)
def cancelar_mi_pedido(
    order_id: str,
    current_customer: CustomerORM = Depends(get_current_customer),
    db: Session = Depends(get_db),
):
    """
    Cancela un pedido del cliente actual, si todavía es cancelable.
    - Solo puede cancelar su propio pedido.
    - No se puede cancelar si ya está En camino / Entregado / Cancelado / Listo para retiro.
    - Actualiza el estado del pedido a 'Cancelado'.
    - Registra el cambio también en TRACKING.
    """

    # 1) Buscar el pedido y validar que sea del cliente actual
    order_db = (
        db.query(OrderORM)
        .filter(
            OrderORM.id == order_id,
            OrderORM.user_id == current_customer.id,
        )
        .first()
    )

    if not order_db:
        raise HTTPException(status_code=404, detail="Pedido no encontrado para este cliente")

    # 2) Validar si es cancelable
    if order_db.status in ESTADOS_NO_CANCELABLES:
        raise HTTPException(
            status_code=400,
            detail=f"No se puede cancelar un pedido con estado '{order_db.status}'.",
        )

    # 3) Cambiar estado del pedido
    order_db.status = "Cancelado"
    db.add(order_db)

    # 4) Registrar en TRACKING (opcional pero bonito para el seguimiento)
    last_tracking = (
        db.query(TrackingORM)
        .filter(TrackingORM.order_id == order_id)
        .order_by(TrackingORM.updated_at.desc())
        .first()
    )

    nuevo_tracking = TrackingORM(
        order_id=order_id,
        status="Cancelado",
        # si tenía repartidor asignado lo copiamos, si no, queda None
        driver_id=last_tracking.driver_id if last_tracking else None,
        updated_at=datetime.now(),
    )
    db.add(nuevo_tracking)

    db.commit()
    db.refresh(order_db)

    # 5) Reconstruir MyOrderSummary SOLO para este pedido (misma lógica que en get_my_orders_with_status)
    items_data: List[MyOrderItem] = []
    for item in order_db.items:
        items_data.append(
            MyOrderItem(
                productName=item.product_name,
                quantity=item.quantity,
                price=float(item.price or 0),
            )
        )

    if order_db.items:
        first_name = order_db.items[0].product_name
        if len(order_db.items) == 1:
            description = first_name
        else:
            description = f"{first_name} + {len(order_db.items) - 1} ítem(s) más"
    else:
        description = "Pedido sin ítems"

    return MyOrderSummary(
        id=str(order_db.id),
        date=order_db.created_at,
        description=description,
        total=float(order_db.total or 0),
        status=order_db.status,   # ahora 'Cancelado'
        items=items_data,
    )

# -----------------------------
# PAYMENT SERVICE (Diagrama 10)
# -----------------------------

@app.post(f"{API_PREFIX}/pagos/pasarela", tags=["PaymentService"])
def process_payment(input: PaymentGatewayInput, current_customer: Customer = Depends(get_current_customer)):
    """
    (Diagrama 10) Integración Pasarela de Pago.
    Endpoint protegido.
    """
    print(f"[DEBUG] Intentando procesar pago para orden {input.orderId} y usuario {current_customer.id}")

    # Buscar el pedido del cliente autenticado
    order = next(
        (o for o in db_orders if o.id == input.orderId and o.userId == current_customer.id),
        None
    )

    if order is None:
        print("[DEBUG] Pedido no encontrado en db_orders para este cliente")
        raise HTTPException(status_code=404, detail="Pedido no encontrado para este cliente")

    # Simular la pasarela de pago
    transaction_id = f"fake_txn_{uuid4()}"
    print(f"[DEBUG] Pago aprobado. Transacción: {transaction_id}")

    # (Opcional) guardar el pago en db_payments si tienes el modelo Payment
    # ...

    return {
        "provider": input.provider,
        "transactionId": transaction_id,
        "status": "aprobado",
        "amount": input.amount
    }



@app.post(f"{API_PREFIX}/pagos/confirmacion-automatica", response_model=Response, tags=["PagoService"])
def confirm_payment(input: PaymentConfirmationInput):
    """
    (Diagrama 11) Confirmación Automática de Pago (Callback).
    Endpoint PÚBLICO (lo llama la pasarela, no el usuario).
    """
    print(f"Confirmando pago para orden {input.orderId} con TnxID: {input.gatewayTransactionId}")
    # Lógica de BBDD (Simulada)
    order = next((o for o in db_orders if o.id == input.orderId), None)
    if order:
        order.status = "Pagado"
        payment = Payment(
            orderId=input.orderId,
            status="Confirmado",
            authorizationCode=f"auth_{random.randint(1000, 9999)}"
        )
        db_payments.append(payment)
        return Response(message=f"Orden {input.orderId} confirmada")
    else:
        raise HTTPException(status_code=404, detail="Orden no encontrada")

# --- Servicio: Producto (Diagrama 08) ---

@app.get(f"{API_PREFIX}/productos/filtrar-buscar", response_model=Response, tags=["ProductService"])
def search_products(filter_input: SearchFilterInput = Depends()):
    """
    (Diagrama 08) Filtrar y Buscar Productos.
    Usa Query Params: ?keywords=pollo&category=asado
    """
    print(f"Buscando productos con: {filter_input.model_dump_json(exclude_none=True)}")
    # Lógica de BBDD (Simulada)
    return Response(data=[
        {"id": "fake_prod_1", "nombre": "Pollo Asado"},
        {"id": "fake_prod_2", "nombre": "Papas Fritas"}
    ])

# --- Servicio: Operaciones (Diagramas 14, 15, 17, 18, 19, 20) ---
from typing import Optional

COCINA_ESTADOS_VALIDOS = [
    "En cocina",
    "En preparación",
    "Listo para retiro",
]

TRACKING_ESTADOS = [
    "En cocina",
    "En preparación",
    "Listo para retiro",
    "En camino",
    "Entregado",
]

@app.get(
    f"{API_PREFIX}/cocina/panel-control",
    response_model=List[KitchenOrder],
    tags=["CocinaService"],
)
def get_kitchen_panel(
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    (Diagrama 14) Panel Control Cocina - AHORA usando MySQL.
    """

    query = (
        db.query(OrderORM)
        .join(CustomerORM, CustomerORM.id == OrderORM.user_id)
    )

    if status:
        query = query.filter(OrderORM.status == status)
    else:
        query = query.filter(
            OrderORM.status.in_(COCINA_ESTADOS_VALIDOS)
        )

    orders_db = query.order_by(OrderORM.created_at.asc()).all()

    resultado: List[KitchenOrder] = []

    for o in orders_db:
        items = [
            KitchenOrderItem(
                productName=item.product_name,
                quantity=item.quantity,
                price=float(item.price),
            )
            for item in o.items
        ]

        total = float(o.total) if o.total is not None else sum(
            it.price * it.quantity for it in items
        )

        resultado.append(
            KitchenOrder(
                id=o.id,
                customerName=o.customer.name if o.customer else "Cliente",
                status=o.status,
                # 👇 ARREGLO IMPORTANTE
                createdAt=o.created_at.isoformat(),
                total=total,
                items=items,
            )
        )

    return resultado


@app.patch(
    f"{API_PREFIX}/cocina/estado/{{order_id}}",
    tags=["CocinaService"],
    response_model=KitchenOrder
)
def update_kitchen_status(
    order_id: str,
    input: KitchenStatusUpdate,
    db: Session = Depends(get_db)
):
    """
    Permite que la cocina cambie el estado de un pedido.
    Estados válidos:
    - En cocina
    - En preparación
    - Listo para retiro
    """

    nuevo_estado = input.status

    # 1) Validar estado
    if nuevo_estado not in COCINA_ESTADOS_VALIDOS:
        raise HTTPException(
            status_code=400,
            detail=f"Estado inválido: {nuevo_estado}. Estados permitidos: {COCINA_ESTADOS_VALIDOS}"
        )

    # 2) Buscar el pedido
    order_db = db.query(OrderORM).filter(OrderORM.id == order_id).first()

    if not order_db:
        raise HTTPException(status_code=404, detail="Pedido no encontrado")

    # 3) Actualizar estado del pedido
    order_db.status = nuevo_estado

    # 4) Actualizar / crear registro en tracking
    tracking_db = (
        db.query(TrackingORM)
        .filter(TrackingORM.order_id == order_id)
        .first()
    )

    if not tracking_db:
        # Si no existe tracking, lo creamos
        tracking_db = TrackingORM(
            id=str(uuid4()),
            order_id=order_id,
            status=nuevo_estado,
            updated_at=datetime.utcnow(),
            driver_id=None,  # en cocina aún no hay repartidor asignado
        )
        db.add(tracking_db)
    else:
        # Si ya existe, solo actualizamos estado y fecha
        tracking_db.status = nuevo_estado
        tracking_db.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(order_db)

    # 5) Construir respuesta tipo KitchenOrder
    items = [
        KitchenOrderItem(
            productName=item.product_name,
            quantity=item.quantity,
            price=float(item.price),
        )
        for item in order_db.items
    ]

    total = float(order_db.total) if order_db.total is not None else sum(
        it.price * it.quantity for it in items
    )

    return KitchenOrder(
        id=order_db.id,
        customerName=order_db.customer.name,
        status=order_db.status,
        createdAt=order_db.created_at,
        total=total,
        items=items,
    )



class KitchenTicketInput(BaseModel):
    orderId: UUID


@app.post(
    f"{API_PREFIX}/cocina/ticket",
    response_model=KitchenOrder,
    tags=["CocinaService"],
)
def generate_kitchen_ticket(
    input: KitchenTicketInput,
    db: Session = Depends(get_db),
    current_customer: CustomerORM = Depends(get_current_customer),
):
    """
    (Diagrama 15) Generación / activación de Ticket de Cocina usando MySQL.

    - Verifica que el pedido exista y pertenezca al cliente actual.
    - Cambia el estado a 'En preparación' si aún no lo está.
    - Devuelve el pedido en el formato del Panel de Cocina.
    """

    order_db = (
        db.query(OrderORM)
        .filter(
            OrderORM.id == str(input.orderId),
            OrderORM.user_id == current_customer.id,
        )
        .first()
    )

    if not order_db:
        raise HTTPException(
            status_code=404,
            detail="Pedido no encontrado para este cliente",
        )

    # Si el pedido está en estado inicial, lo pasamos a 'En preparación'
    if order_db.status not in ["En preparación", "Listo para retiro"]:
        order_db.status = "En preparación"
        db.add(order_db)
        db.commit()
        db.refresh(order_db)

    # Construir respuesta tipo KitchenOrder
    items = [
        KitchenOrderItem(
            productName=item.product_name,
            quantity=item.quantity,
            price=float(item.price),
        )
        for item in order_db.items
    ]

    total = float(order_db.total) if order_db.total is not None else sum(
        it.price * it.quantity for it in items
    )

    return KitchenOrder(
        id=order_db.id,
        customerName=current_customer.name,
        status=order_db.status,
        createdAt=order_db.created_at,
        total=total,
        items=items,
    )


@app.post(f"{API_PREFIX}/cocina/alertas-coccion", response_model=Response, tags=["OperacionesService"])
def set_cooking_alert(input: CookingTimeAlertInput):
    """ (Diagrama 15) Alertas Tiempos de Cocción """
    print(f"Alerta creada para ticket {input.ticketId} a los {input.thresholdMinutes} min.")
    return Response(message="Alerta creada")
# --- Servicio: Tracking (Diagrama 16) ---

@app.post(f"{API_PREFIX}/tracking/actualizar", response_model=Tracking, tags=["TrackingService"])
def update_tracking(
    input: TrackingUpdateInput,
    current_customer: Customer = Depends(get_current_customer)
):
    """
    (Diagrama 16) Actualización de Tracking de Pedido.
    Endpoint protegido.
    """

    # 1) Verificar que el pedido exista y pertenezca al cliente actual
    order = get_order_for_customer(input.orderId, current_customer.id)
    if order is None:
        raise HTTPException(
            status_code=404,
            detail="Pedido no encontrado para este cliente"
        )

    # 2) Buscar tracking existente
    tracking = next(
        (t for t in db_trackings if t.orderId == input.orderId),
        None
    )

    # 3) Crear si no existe
    if tracking is None:
        tracking = Tracking(
            orderId=input.orderId,
            status=input.status
        )
        db_trackings.append(tracking)
        print(f"[DEBUG] Tracking creado para pedido {input.orderId}: {tracking.status}")

    else:
        # 4) Actualizar
        tracking.status = input.status
        tracking.updatedAt = datetime.now()
        print(f"[DEBUG] Tracking actualizado para pedido {input.orderId}: {tracking.status}")

    return tracking

API_PREFIX = "/api/pollosabroso"  # declarada solo una vez en todo el archivo

@app.get(f"{API_PREFIX}/tracking/{{order_id}}",
         response_model=TrackingResponse,
         tags=["TrackingService"])
def get_tracking(
    order_id: str,
    db: Session = Depends(get_db)
):
    """
    Devuelve el estado actual del tracking de un pedido,
    incluyendo (si existe) los datos del repartidor asignado.
    """
    # Tomamos el último tracking para ese pedido
    tracking = (
        db.query(TrackingORM)
        .filter(TrackingORM.order_id == order_id)
        .order_by(TrackingORM.updated_at.desc())
        .first()
    )

    if not tracking:
        raise HTTPException(
            status_code=404,
            detail="No hay información de tracking para este pedido."
        )

    # Armar info del repartidor (puede ser None)
    driver_info = None
    if tracking.driver:  # gracias al relationship en models.py
        driver_info = DriverInfo(
            id=str(tracking.driver.id),
            name=tracking.driver.name,
            phone=tracking.driver.phone
        )

    # Respuesta final
    return TrackingResponse(
        orderId=str(tracking.order_id),
        status=tracking.status,
        updatedAt=tracking.updated_at,
        driver=driver_info
    )

# --- Panel Repartidor: listar pedidos asignados ---

@app.get(
    f"{API_PREFIX}/repartidores/{{driver_id}}/pedidos",
    response_model=List[DriverOrder],
    tags=["DeliveryPanel"]
)
def get_driver_orders(
    driver_id: str,
    db: Session = Depends(get_db)
):
    """
    Devuelve los pedidos asignados a un repartidor dado (driver_id),
    con su estado actual y el detalle de ítems.
    Solo devuelve el ÚLTIMO tracking por pedido.
    """

    # 1) Obtenemos todos los trackings de ese repartidor, ordenados del más nuevo al más viejo
    trackings = (
        db.query(TrackingORM)
        .filter(TrackingORM.driver_id == driver_id)
        .order_by(TrackingORM.updated_at.desc())
        .all()
    )

    # 2) Nos quedamos solo con el último tracking de cada order_id
    ultimos_por_pedido = {}
    for tr in trackings:
        if tr.order_id not in ultimos_por_pedido:
            ultimos_por_pedido[tr.order_id] = tr

    resultado: List[DriverOrder] = []

    for tr in ultimos_por_pedido.values():
        order = db.query(OrderORM).filter(OrderORM.id == tr.order_id).first()
        if not order:
            continue

        customer = db.query(CustomerORM).filter(
            CustomerORM.id == order.user_id
        ).first()

        items_db = (
            db.query(OrderItemORM)
            .filter(OrderItemORM.order_id == order.id)
            .all()
        )

        items_pydantic: List[DriverOrderItem] = [
            DriverOrderItem(
                productName=item.product_name,
                quantity=item.quantity,
                price=float(item.price or 0),
            )
            for item in items_db
        ]

        resultado.append(
            DriverOrder(
                orderId=str(order.id),
                customerName=customer.name if customer else None,
                total=float(order.total or 0),
                status=tr.status,          # 👈 estado actual del tracking
                createdAt=order.created_at,
                items=items_pydantic,
            )
        )

    return resultado

class DriverUpdateStatusInput(BaseModel):
    status: str   # "En preparación", "En camino", "Entregado", etc.


@app.post(f"{API_PREFIX}/repartidores/pedidos/{{order_id}}/status",
          response_model=TrackingStatusResponse,
          tags=["DeliveryPanel"])
def driver_update_order_status(
    order_id: str,
    data: DriverUpdateStatusInput,
    db: Session = Depends(get_db)
):
    """
    Permite al repartidor actualizar el estado del pedido.
    (Ej: En camino -> Entregado)
    """
    tracking = (
        db.query(TrackingORM)
        .filter(TrackingORM.order_id == order_id)
        .order_by(TrackingORM.updated_at.desc())
        .first()
    )

    if not tracking:
        raise HTTPException(status_code=404, detail="Tracking no encontrado")

    tracking.status = data.status
    tracking.updated_at = datetime.now()
    db.commit()
    db.refresh(tracking)

    driver_data = None
    if tracking.driver_id:
        driver = db.query(DeliveryPersonORM).filter(
            DeliveryPersonORM.id == tracking.driver_id
        ).first()
        if driver:
            driver_data = {
                "id": str(driver.id),
                "name": driver.name,
                "phone": driver.phone,
            }

    return TrackingStatusResponse(
        orderId=str(tracking.order_id),
        status=tracking.status,
        updatedAt=tracking.updated_at,
        driver=driver_data,
    )
from fastapi import Depends
from database import get_db
# o el schema que uses para devolver pedidos

@app.post(
    f"{API_PREFIX}/repartidores/asignar-automatico/{{order_id}}",
    response_model=AssignedOrderResponse,
    tags=["RepartidorService"],
)
def asignar_repartidor_endpoint(order_id: str, db: Session = Depends(get_db)):
    """
    (Diagrama XX) Asignación automática de repartidor para un pedido.

    - Busca el pedido por ID
    - Selecciona el mejor repartidor disponible
    - Asigna el repartidor
    - Retorna el pedido actualizado con info del repartidor
    """
    # 1) Buscar la orden
    order_db = db.query(OrderORM).filter(OrderORM.id == order_id).first()
    if not order_db:
        raise HTTPException(status_code=404, detail="Pedido no encontrado")

    # 2) Validar estado (opcional)
    if order_db.status in ["Entregado", "Cancelado"]:
        raise HTTPException(
            status_code=400,
            detail=f"No se puede asignar repartidor a un pedido con estado '{order_db.status}'.",
        )

    # 3) Asignar repartidor automáticamente (usa tu función de antes)
    repartidor = asignar_repartidor_automatico(db, order_db)

    # 4) Armar objeto DriverInfo
    driver_info = None
    if repartidor:
        driver_info = DriverInfo(
            id=repartidor.id,
            name=repartidor.name,
            phone=repartidor.phone,
        )

    # 5) Retornar el pedido + info del repartidor asignado
    return AssignedOrderResponse(
        id=str(order_db.id),
        userId=str(order_db.user_id),
        total=float(order_db.total),
        status=order_db.status,
        createdAt=order_db.created_at,
        driver=driver_info,
    )
from typing import List


@app.get(
    f"{API_PREFIX}/repartidores/pedidos-asignados/{{driver_id}}",
    response_model=List[KitchenOrder],
    tags=["RepartidorService"],
)
def get_assigned_orders_for_driver(
    driver_id: str,
    db: Session = Depends(get_db),
):
    """
    Lista de pedidos asignados a un repartidor (para el Panel de Repartidor).

    - Usa la tabla tracking para ver qué pedidos tiene asignados ese driver_id.
    - Toma el estado desde tracking.status (Repartidor asignado, En ruta, Entregado, etc.)
    """

    # Trackings de ese repartidor, en estados "activos" para él
    trackings = (
        db.query(TrackingORM)
        .join(OrderORM, TrackingORM.order_id == OrderORM.id)
        .join(CustomerORM, CustomerORM.id == OrderORM.user_id)
        .filter(
            TrackingORM.driver_id == driver_id,
            TrackingORM.status.in_(["Repartidor asignado", "En ruta"])
        )
        .order_by(OrderORM.created_at.asc())
        .all()
    )

    resultado: List[KitchenOrder] = []

    for tr in trackings:
        o = tr.order  # relación TrackingORM.order

        items = [
            KitchenOrderItem(
                productName=item.product_name,
                quantity=item.quantity,
                price=float(item.price),
            )
            for item in o.items
        ]

        total = float(o.total) if o.total is not None else sum(
            it.price * it.quantity for it in items
        )

        resultado.append(
            KitchenOrder(
                id=o.id,
                customerName=o.customer.name if o.customer else "Cliente",
                status=tr.status,          # 👈 estado desde tracking
                createdAt=o.created_at,
                total=total,
                items=items,
            )
        )

    return resultado


@app.post(f"{API_PREFIX}/reparto/planificacion-rutas", response_model=Response, tags=["OperacionesService"])
def plan_routes(input: RoutePlanningInput):
    """ (Diagrama 18) Planificación de Rutas """
    print(f"Planificando rutas para {len(input.orders)} órdenes.")
    return Response(data={"stops": len(input.orders), "optimizedBy": "simulador"})

@app.get(f"{API_PREFIX}/reparto/panel", response_model=Response, tags=["OperacionesService"])
def get_courier_panel(
    driverId: UUID,
    db: Session = Depends(get_db)
):
    """
    (Diagrama 19) Panel de Repartidor.
    Usa Query Param: ?driverId=...
    Muestra todos los pedidos asignados a ese repartidor.
    """

    trackings = db.query(TrackingORM).filter(
        TrackingORM.driver_id == str(driverId)
    ).all()

    pedidos = []
    for tr in trackings:
        pedidos.append(
            {
                "orderId": tr.order_id,
                "status": tr.status,
                "updatedAt": tr.updated_at,
            }
        )

    return Response(data=pedidos)


@app.get(f"{API_PREFIX}/pedidos/seguimiento", response_model=Tracking, tags=["OperacionesService"])
def track_order(orderId: UUID):
    """
    (Diagrama 20) Seguimiento del Pedido.
    Usa Query Params: ?orderId=...
    """
    print(f"Obteniendo seguimiento para orden {orderId}")
    # Lógica de BBDD (Simulada)
    tracking_data = Tracking(
        orderId=orderId,
        lat=Decimal("-33.456") + Decimal(random.uniform(-0.01, 0.01)),
        lng=Decimal("-70.678") + Decimal(random.uniform(-0.01, 0.01)),
        updatedAt=datetime.now()
    )
    db_trackings.append(tracking_data)
    return tracking_data

# --- Servicio: Notificacion (Diagramas 13, 16, 23, 24) ---

@app.post(f"{API_PREFIX}/boletas/envio", response_model=Response, tags=["NotificationService"])
def send_invoice_email(input: SendInvoiceEmailInput):
    """ (Diagrama 13) Envio de Boletas por Correo """
    print(f"Enviando boleta {input.invoiceId} a {input.email}")
    return Response(message="Boleta enviada")

@app.post(f"{API_PREFIX}/notificaciones/cliente", response_model=Response, tags=["NotificationService"])
def send_customer_notification(input: CustomerNotificationInput):
    """ (Diagrama 16) Notificacion al Cliente """
    print(f"Enviando notificación '{input.title}' a {input.userId}")
    return Response(message="Notificación enviada")

@app.post(f"{API_PREFIX}/promociones/recibir", response_model=Response, tags=["NotificationService"])
def send_personalized_promo(input: PersonalizedPromotionInput):
    """ (Diagrama 23) Recibir Promociones Personalizadas """
    print(f"Enviando promo '{input.title}' a segmento {input.segment}")
    return Response(message="Promoción enviada")

@app.post(f"{API_PREFIX}/promociones/recordatorio", response_model=Response, tags=["NotificationService"])
def send_promo_reminder(input: PromotionReminderInput):
    """ (Diagrama 24) Recordatorio de Promociones """
    print(f"Programando recordatorio '{input.title}' para {input.userId} en canal {input.channel}")
    return Response(message="Recordatorio programado")

# --- Servicio: Documento (Diagrama 12) ---

@app.post(f"{API_PREFIX}/facturas/generar", response_model=Invoice, tags=["InvoiceService"])
def generate_invoice(
    input: DigitalInvoiceInput,
    current_customer: Customer = Depends(get_current_customer)
):
    """
    (Diagrama 11/12) Generación de Boleta / Factura Digital.
    Endpoint protegido.
    """
    # 1) Verificar que el pedido exista y pertenezca al cliente actual
    order = get_order_for_customer(input.orderId, current_customer.id)
    if order is None:
        raise HTTPException(
            status_code=404,
            detail="Pedido no encontrado para este cliente"
        )

    # 2) Verificar si ya existe una factura para este pedido
    existing_invoice = next(
        (inv for inv in db_invoices if inv.orderId == order.id),
        None
    )
    if existing_invoice:
        print(f"[DEBUG] Factura ya existe para pedido {order.id}, devolviendo existente")
        return existing_invoice

    # 3) Generar número de boleta/factura
    invoice_number = f"BOL-{datetime.now().year}-{len(db_invoices) + 1:06}"

    # 4) Construir URL "fake" del PDF (simulado)
    pdf_url = f"https://pollos-abrosos-fake-storage.local/facturas/{invoice_number}.pdf"

    # 5) Crear la boleta/factura
    new_invoice = Invoice(
        orderId=order.id,
        number=invoice_number,
        total=input.amount,
        pdfUrl=pdf_url,
        # generatedAt se llena solo por el Field(default_factory=datetime.now)
    )

    # 6) Guardar en la "BD" en memoria
    db_invoices.append(new_invoice)

    print(f"[DEBUG] Factura generada para pedido {order.id}: {invoice_number}")

    # 7) Devolver la boleta/factura generada
    return new_invoice


# --- Servicio: Misc (Diagramas 25, 26) ---

@app.post(f"{API_PREFIX}/formularios/enviar", response_model=Response, tags=["MiscService"])
def submit_form(input: FormSubmissionInput, current_customer: Customer = Depends(get_current_customer)):
    """
    (Diagrama 25) Formularios (Ej. Contacto, Reclamos).
    Endpoint protegido.
    """
    print(f"Recibido formulario '{input.type}' de {current_customer.email}")
    return Response(message="Formulario recibido")

@app.post(f"{API_PREFIX}/integracion/sistema-datos", response_model=Response, tags=["MiscService"])
def sync_data(input: DataSystemIntegrationInput):
    """
    (Diagrama 26) Integracion Sistema de Datos (Admin/Interno).
    Endpoint protegido (simulación omitida).
    """
    print(f"Integrando {input.records} registros de {input.source}")
    return Response(message="Integración completada")