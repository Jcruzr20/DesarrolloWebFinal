# database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Datos de conexión
DB_USER = "root"
DB_PASSWORD = ""   # deja vacío si no tienes clave
DB_HOST = "localhost"
DB_PORT = "3306"
DB_NAME = "pollosabrosos"

# Driver de mysqlclient → "mysqldb"
DATABASE_URL = f"mysql+mysqldb://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Motor de SQLAlchemy
engine = create_engine(
    DATABASE_URL,
    echo=False,      # pon True si quieres ver todas las queries
    future=True,
)

# Sesiones
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base para los modelos
Base = declarative_base()

# ⚠️ ESTA FUNCIÓN ES LA QUE FALTABA
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
