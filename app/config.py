import os
from datetime import timedelta
from dotenv import load_dotenv
load_dotenv()

class Config:
    # Base de datos
    SQLALCHEMY_DATABASE_URI = (
        f"mssql+pyodbc://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}"
        f"@{os.getenv('DB_SERVER')}/{os.getenv('DB_NAME')}"
        "?driver=ODBC+Driver+17+for+SQL+Server"
    )

    # Seguridad
    SECRET_KEY = os.getenv('SECRET_KEY', "co2Y0J2J5keyx&/%&/%")
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    JWT_TOKEN_LOCATION = ['cookies']
    JWT_COOKIE_SECURE = False  # True en producción
    BCRYPT_LOG_ROUNDS = 12
    JWT_COOKIE_CSRF_PROTECT = False
    JWT_ACCESS_COOKIE_NAME = 'access_token'
    JWT_ACCESS_CSRF_HEADER_NAME = "X-CSRF-TOKEN"
    JWT_SESSION_COOKIE = False
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)

    # Configuración mejorada de CSRF
    WTF_CSRF_CHECK_DEFAULT = True
    WTF_CSRF_SSL_STRICT = False  # True en producción con HTTPS
    WTF_CSRF_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE']
    WTF_CSRF_FIELD_NAME = 'csrf_token'
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hora

    SESSION_COOKIE_SECURE = False  # True en producción
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Email
    MAIL_SERVER = 'smtp.hostinger.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'soporte@portaltulum.com'
    MAIL_PASSWORD = '12Tulum12.'
    MAIL_DEFAULT_SENDER = 'soporte@portaltulum.com'
    APP_LOGIN_URL = 'https://tudominio.com/login'  # URL del sistema

    PEPPER = "TulumxEver"