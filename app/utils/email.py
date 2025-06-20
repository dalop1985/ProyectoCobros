# app/utils/email.py
from flask_mail import Message
from flask import current_app, render_template
from app import mail


def enviar_correo_bienvenida(usuario, contrasena_temporal, es_actualizacion=False):
    """Envía correo de bienvenida o actualización con credenciales"""
    try:
        # Determinar asunto y plantilla según tipo
        subject = "Actualización de Credenciales" if es_actualizacion else "Bienvenido al Sistema de Cobros Municipales"
        template = 'emails/actualizacion.html' if es_actualizacion else 'emails/bienvenida.html'

        # Renderizar plantilla HTML
        html = render_template(
            template,
            nombre_completo=usuario.nombre_completo(),
            usuario=usuario.usuario,
            password=contrasena_temporal,
            login_url=current_app.config['APP_LOGIN_URL']
        )

        # Crear mensaje
        msg = Message(
            subject=subject,
            recipients=[usuario.email],
            html=html,
            sender=current_app.config['MAIL_DEFAULT_SENDER']
        )

        # Enviar correo
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Error enviando correo a {usuario.email}: {str(e)}")
        return False


def enviar_correo_contrasena_cambiada(usuario):
    """Envía correo notificando cambio de contraseña"""
    try:
        # Renderizar plantilla HTML
        html = render_template(
            'emails/contrasena_cambiada.html',
            nombre_completo=usuario.nombre_completo(),
            login_url=current_app.config['APP_LOGIN_URL']
        )

        # Crear mensaje
        msg = Message(
            subject="Su contraseña ha sido actualizada",
            recipients=[usuario.email],
            html=html,
            sender=current_app.config['MAIL_DEFAULT_SENDER']
        )

        # Enviar correo
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Error enviando correo de cambio de contraseña: {str(e)}")
        return False


def enviar_correo_codigo_recuperacion(usuario, codigo):
    """Envía correo con código de recuperación"""
    try:
        # Renderizar plantilla HTML
        html = render_template(
            'emails/codigo_recuperacion.html',
            nombre_completo=usuario.nombre_completo(),
            codigo=codigo,
            login_url=current_app.config['APP_LOGIN_URL']
        )

        # Crear mensaje
        msg = Message(
            subject="Código de Recuperación",
            recipients=[usuario.email],
            html=html,
            sender=current_app.config['MAIL_DEFAULT_SENDER']
        )

        # Enviar correo
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Error enviando correo de recuperación: {str(e)}")
        return False