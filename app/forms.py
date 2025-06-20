from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, BooleanField
from wtforms.fields.numeric import FloatField
from wtforms.fields.simple import SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Optional, Email, NumberRange, Regexp
from wtforms.fields import EmailField
from wtforms import DateTimeField
from flask_wtf.file import FileField, FileAllowed

from app.models import Configuracion, Usuario
from wtforms.validators import ValidationError

import re

class UsuarioForm(FlaskForm):


    usuario = StringField('Usuario', validators=[
        DataRequired(message='El nombre de usuario es requerido'),
        Length(min=4, max=50, message='El usuario debe tener entre 4 y 50 caracteres')
    ])

    email = EmailField('Email', validators=[  # Cambiar de StringField a EmailField
        DataRequired(message='El email es requerido'),
        Length(max=100)
    ])

    nombre = StringField('Nombre', validators=[
        DataRequired(message='El nombre es requerido'),
        Length(min=2, max=50)
    ])

    apellido_paterno = StringField('Apellido Paterno', validators=[
        DataRequired(message='El apellido paterno es requerido'),
        Length(min=2, max=50)
    ])

    apellido_materno = StringField('Apellido Materno', validators=[
        Optional(),
        Length(max=50)
    ])

    fecha_nacimiento = DateTimeField('Fecha de Nacimiento',
                                 format='%Y-%m-%d',
                                 validators=[DataRequired(message='La fecha de nacimiento es requerida')])

    rol = SelectField('Rol', choices=[
        ('admin', 'Administrador'),
        ('user', 'Usuario')
    ], validators=[DataRequired()])

    activo = BooleanField('Activo', default=True)

    password = PasswordField('Contraseña', validators=[
        Optional(),
        Length(min=8, message='La contraseña debe tener al menos 8 caracteres'),
        EqualTo('confirm_password', message='Las contraseñas deben coincidir')
    ])

    confirm_password = PasswordField('Confirmar Contraseña')

    def validate_email(self, field):
        """Valida que el email no esté en uso"""
        # Solo validar si estamos creando nuevo usuario o cambiando email
        if hasattr(self, 'usuario_obj') and self.usuario_obj.email == field.data:
            return

        if Usuario.query.filter_by(email=field.data).first():
            raise ValidationError('Este correo electrónico ya está registrado')

    def validate_usuario(self, field):
        """Valida que el usuario no esté en uso"""
        if hasattr(self, 'usuario_obj') and self.usuario_obj.usuario == field.data:
            return

        if Usuario.query.filter_by(usuario=field.data).first():
            raise ValidationError('Este nombre de usuario ya está registrado')

class ConfiguracionForm(FlaskForm):
    logo_municipio = FileField('Logo Municipio',
                              validators=[FileAllowed(['jpg', 'png', 'svg'], 'Solo imágenes')])
    logo_admin = FileField('Logo Administración',
                          validators=[FileAllowed(['jpg', 'png', 'svg'], 'Solo imágenes')])
    color_principal = StringField('Color Principal', validators=[DataRequired()])
    color_secundario = StringField('Color Secundario', validators=[DataRequired()])
    telefono_emergencia = StringField('Teléfono Emergencias', validators=[DataRequired()])
    slogan = StringField('Slogan Municipal', validators=[DataRequired()])
    presidente_municipal = StringField('Presidente Municipal', validators=[DataRequired()])
    direccion = StringField('Dirección', validators=[DataRequired()])
    horario_atencion = StringField('Horario de Atención')
    email_contacto = StringField('Email Contacto', validators=[Email()])
    facebook = StringField('Facebook')
    twitter = StringField('Twitter')
    submit = SubmitField('Guardar Configuración')
    fuente_principal = SelectField('Fuente Principal',
                                   choices=[(f, f) for f in Configuracion.obtener_fuentes_disponibles()])
    fuente_titulos = SelectField('Fuente para Títulos',
                                 choices=[(f, f) for f in Configuracion.obtener_fuentes_disponibles()])
    imagen_fondo = FileField('Imagen de Fondo',
                             validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Solo imágenes')])
    opacidad_fondo = FloatField('Opacidad del Fondo',
                                validators=[NumberRange(min=0, max=1, message='Valor entre 0 y 1')])
    color_texto = StringField('Color de Texto',
                              validators=[DataRequired(), Regexp(r'^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$',
                                                                 message='Formato hexadecimal inválido')])


class CambioContrasenaForm(FlaskForm):
    nueva_contrasena = PasswordField('Nueva Contraseña', validators=[
        DataRequired(),
        Length(min=8, max=15, message='La contraseña debe tener entre 8 y 15 caracteres')
    ])
    confirmar_contrasena = PasswordField('Confirmar Contraseña', validators=[
        DataRequired(),
        EqualTo('nueva_contrasena', message='Las contraseñas no coinciden')
    ])
    submit = SubmitField('Cambiar Contraseña')

    def validate_nueva_contrasena(self, field):
        # Validar que tenga al menos una mayúscula
        if not re.search(r'[A-Z]', field.data):
            raise ValidationError('La contraseña debe contener al menos una letra mayúscula')

        # Validar que tenga al menos un número
        if not re.search(r'[0-9]', field.data):
            raise ValidationError('La contraseña debe contener al menos un número')

        # Validar que tenga al menos un carácter especial
        if not re.search(r'[.,\-!#$%&/=?¿¡+{}[\]()]', field.data):
            raise ValidationError(
                'La contraseña debe contener al menos un carácter especial (. , - ! # $ % & / = ? ¿ ¡ + { } [ ] ( ))')


class SolicitudRecuperacionForm(FlaskForm):
    usuario_o_email = StringField('Usuario o Correo Electrónico', validators=[DataRequired()])
    captcha = StringField('Captcha', validators=[Optional()])  # Solo requerido después de varios intentos
    submit = SubmitField('Enviar Código')


class VerificarCodigoForm(FlaskForm):
    codigo = StringField('Código de Verificación', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verificar')


class NuevaContrasenaForm(FlaskForm):
    nueva_contrasena = PasswordField('Nueva Contraseña', validators=[
        DataRequired(),
        Length(min=8, max=15, message='La contraseña debe tener entre 8 y 15 caracteres')
    ])
    confirmar_contrasena = PasswordField('Confirmar Contraseña', validators=[
        DataRequired(),
        EqualTo('nueva_contrasena', message='Las contraseñas no coinciden')
    ])
    submit = SubmitField('Establecer Nueva Contraseña')

    # Agregar validaciones de seguridad (igual que en CambioContrasenaForm)
    def validate_nueva_contrasena(self, field):
        # Validar que tenga al menos una mayúscula
        if not re.search(r'[A-Z]', field.data):
            raise ValidationError('La contraseña debe contener al menos una letra mayúscula')

        # Validar que tenga al menos un número
        if not re.search(r'[0-9]', field.data):
            raise ValidationError('La contraseña debe contener al menos un número')

        # Validar que tenga al menos un carácter especial
        if not re.search(r'[.,\-!#$%&/=?¿¡+{}[\]()]', field.data):
            raise ValidationError(
                'La contraseña debe contener al menos un carácter especial (. , - ! # $ % & / = ? ¿ ¡ + { } [ ] ( ))')