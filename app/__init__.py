import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail

db = SQLAlchemy()
jwt = JWTManager()
bcrypt = Bcrypt()
csrf = CSRFProtect()
mail = Mail()

def create_app():

    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'co2Y0J2J5keyx&/%&/'
    app.config['WTF_CSRF_SECRET_KEY'] = 'otra-clave-secreta-para-csrf'
    app.config.from_object('app.config.Config')
    # Exponer db en app para acceso global
    app.db = db

    # Inicializar extensiones
    db.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)
    csrf = CSRFProtect(app)  # Inicializar CSRF aquí
    mail.init_app(app)

    # Registrar blueprints
    from .routes import routes_bp, admin_bp
    app.register_blueprint(routes_bp)
    app.register_blueprint(admin_bp)

    # Eximir blueprints después de registrarlos
    csrf.exempt(routes_bp)
    csrf.exempt(admin_bp)

    # Registrar middleware
    from .middleware import session_handler
    app.before_request(session_handler)

    # Crear configuración inicial si no existe
    with app.app_context():
        from .models import Configuracion
        Configuracion.obtener_config()

    # Configurar carpeta de subidas
    app.config['UPLOAD_FOLDER_LOGOS'] = os.path.join(app.instance_path, 'static', 'images', 'logos')
    os.makedirs(app.config['UPLOAD_FOLDER_LOGOS'], exist_ok=True)

    # DEBUG: Listar todas las rutas (temporal)
    #with app.app_context():
    #    print("\nRutas registradas:")
    #    for rule in app.url_map.iter_rules():
    #        print(f"{rule.endpoint}: {rule}")
    #    print()


    return app