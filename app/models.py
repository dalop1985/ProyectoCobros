from flask import current_app
from datetime import datetime, timedelta
import secrets
from app import db


class Usuario(db.Model):
    __tablename__ = 'usuarios'

    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    rol = db.Column(db.String(20), nullable=False, default='user')
    nombre = db.Column(db.String(50), nullable=False)
    apellido_paterno = db.Column(db.String(50), nullable=False)
    apellido_materno = db.Column(db.String(50), nullable=True)
    fecha_nacimiento = db.Column(db.DateTime, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    activo = db.Column(db.Boolean, default=True)
    nuevo_user = db.Column(db.Boolean, default=True)
    creado_en = db.Column(db.DateTime, default=db.func.current_timestamp())
    actualizado_en = db.Column(db.DateTime, default=db.func.current_timestamp(),
                               onupdate=db.func.current_timestamp())

    # CORRECCIÓN: Eliminar la redefinición de estas columnas
    creado_por_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'))
    actualizado_por_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'))

    # Relación con registros de acceso
    access_logs = db.relationship('AccessLog', backref='user', lazy='dynamic')

    # CORRECCIÓN: Relaciones recursivas correctamente definidas
    creado_por = db.relationship(
        'Usuario',
        remote_side=[id],
        foreign_keys=[creado_por_id],
        backref=db.backref('usuarios_creados', lazy='dynamic')
    )

    actualizado_por = db.relationship(
        'Usuario',
        remote_side=[id],
        foreign_keys=[actualizado_por_id],
        backref=db.backref('usuarios_actualizados', lazy='dynamic')
    )


    def check_password(self, password):
        """Verifica si la contraseña coincide con el hash almacenado"""
        from app import bcrypt
        pepper = "TulumxEver"
        password_pepper = (password + pepper)[:72]
        #self.password_hash = bcrypt.generate_password_hash(password_pepper).decode('utf-8')
        return bcrypt.check_password_hash(self.password_hash, password_pepper)

    def nombre_completo(self):
        """Devuelve el nombre completo formateado"""
        partes = [self.nombre, self.apellido_paterno]
        if self.apellido_materno:
            partes.append(self.apellido_materno)
        return " ".join(partes)

    def __repr__(self):
        return f'<Usuario {self.usuario} - {self.email}>'

    def set_password(self, password):
        """Establece la contraseña del usuario con encriptación fuerte"""
        from app import bcrypt
        pepper = current_app.config.get('PEPPER', 'TulumxEver')
        password_pepper = (password + pepper)[:72]
        self.password_hash = bcrypt.generate_password_hash(password_pepper).decode('utf-8')


class AccessLog(db.Model):
    __tablename__ = 'access_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    ip_address = db.Column(db.String(50), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    endpoint = db.Column(db.String(100))
    user_agent = db.Column(db.String(255))
    device_info = db.Column(db.String(100))
    location = db.Column(db.String(100))
    details = db.Column(db.Text, default='')

    # Nuevos campos para información adicional
    request_method = db.Column(db.String(10))  # GET, POST, etc.
    request_path = db.Column(db.String(255))  # Ruta accedida
    request_data = db.Column(db.Text)  # Datos de la solicitud (formularios, etc.)

    # Relación
    #user = db.relationship('Usuario', backref='access_logs')
    #user_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=True)

    def __repr__(self):
        return f'<AccessLog {self.id} - {self.event_type} - {self.timestamp}>'


class Configuracion(db.Model):
    __tablename__ = 'configuraciones'

    id = db.Column(db.Integer, primary_key=True)
    logo_municipio = db.Column(db.String(255), default='logo_municipio.png')
    logo_admin = db.Column(db.String(255), default='logo_admin.png')
    color_principal = db.Column(db.String(7), default='#1e2a3a')
    color_secundario = db.Column(db.String(7), default='#2c3b4e')
    telefono_emergencia = db.Column(db.String(20), default='911')
    slogan = db.Column(db.String(100), default='Servicio y compromiso con nuestra comunidad')
    presidente_municipal = db.Column(db.String(100), default='Lic. Juan Pérez')
    direccion = db.Column(db.String(200), default='Palacio Municipal s/n, Centro')
    horario_atencion = db.Column(db.String(100), default='Lunes a Viernes: 8:00 AM - 4:00 PM')
    email_contacto = db.Column(db.String(100), default='contacto@municipio.gob.mx')
    facebook = db.Column(db.String(100))
    twitter = db.Column(db.String(100))
    fuente_principal = db.Column(db.String(50), default='Arial')
    fuente_titulos = db.Column(db.String(50), default='Roboto')
    imagen_fondo = db.Column(db.String(255), default='fondo_default.jpg')
    opacidad_fondo = db.Column(db.Float, default=0.15)  # Valor entre 0 y 1
    color_texto = db.Column(db.String(7), default='#333333')
    tiempo_inactividad = db.Column(db.Integer, default=20)

    @classmethod
    def obtener_fuentes_disponibles(cls):
        return [
            'Arial', 'Verdana', 'Georgia',
            'Times New Roman', 'Courier New',
            'Roboto', 'Open Sans', 'Montserrat'
        ]

    @classmethod
    def obtener_config(cls):
        """Obtiene la configuración actual (siempre será un solo registro)"""
        config = cls.query.first()
        if not config:
            config = Configuracion()
            db.session.add(config)
            db.session.commit()
        return config


class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    token = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

    user = db.relationship('Usuario', backref='reset_tokens')

    def is_valid(self):
        from datetime import datetime
        return datetime.utcnow() < self.expires_at and not self.used

    @staticmethod
    def generate_token(user, expiration_minutes=10):
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(minutes=expiration_minutes)
        return PasswordResetToken(
            user_id=user.id,
            token=token,
            expires_at=expires_at
        )


class SolicitudBaja(db.Model):
    __tablename__ = 'solicitudes_baja'
    id = db.Column(db.Integer, primary_key=True)

    # CORRECCIÓN: Definir columnas solo una vez
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    fecha_solicitud = db.Column(db.DateTime, default=db.func.current_timestamp())
    motivo = db.Column(db.Text, nullable=False)
    estado = db.Column(db.String(20), default='pendiente')
    admin_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'))
    observaciones = db.Column(db.Text)
    fecha_resolucion = db.Column(db.DateTime)

    # CORRECCIÓN: Relaciones bien definidas
    usuario = db.relationship(
        'Usuario',
        foreign_keys=[usuario_id],
        backref=db.backref('solicitudes_baja', lazy='dynamic')
    )

    admin = db.relationship(
        'Usuario',
        foreign_keys=[admin_id],
        backref=db.backref('solicitudes_resueltas', lazy='dynamic')
    )


class HistoricoBajas(db.Model):
    __tablename__ = 'historico_bajas'

    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    fecha_baja = db.Column(db.DateTime, default=db.func.current_timestamp())
    motivo_baja = db.Column(db.Text)
    admin_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'))
    acciones = db.Column(db.String(20), default='pendiente')

    # Relaciones
    usuario = db.relationship('Usuario', foreign_keys=[usuario_id])
    administrador = db.relationship('Usuario', foreign_keys=[admin_id])