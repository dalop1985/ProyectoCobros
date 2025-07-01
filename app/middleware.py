# app/middleware.py
from flask import request, g, current_app, session, redirect, url_for, flash
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, unset_jwt_cookies
from flask_jwt_extended.exceptions import JWTExtendedException
from app.models import Usuario, Configuracion
import time
import jwt


# app/middleware.py
def session_handler():
    """Middleware para gestionar sesiones, autenticación, CSRF y tiempo de inactividad"""
    try:
        # 1. Eximir rutas públicas
        public_routes = ['main.login', 'static', 'main.session_expired',
                         'main.solicitar_recuperacion_contrasena',
                         'main.verificar_codigo_recuperacion',
                         'main.establecer_nueva_contrasena']

        # Rutas que no deben actualizar la actividad
        no_activity_update_routes = ['main.update_activity', 'main.check_session']

        # Si es una ruta pública, no procesar
        if request.endpoint in public_routes:
            return

        # Verificar si la sesión está marcada como expirada
        if session.get('session_expired_flag'):
            # Solo redirigir si no estamos ya en session_expired
            if request.endpoint != 'main.session_expired':
                return redirect(url_for('main.session_expired'))
            return

        # 2. Verificar JWT para rutas protegidas (manejar tokens expirados)
        try:
            verify_jwt_in_request(optional=True)
        except jwt.ExpiredSignatureError:
            # Token expirado - limpiar y redirigir
            session.clear()
            response = redirect(url_for('main.session_expired'))
            unset_jwt_cookies(response)
            return response
        except JWTExtendedException as e:
            current_app.logger.error(f"Error JWT: {str(e)}")
            return redirect(url_for('main.login'))

        user_id = get_jwt_identity()

        # 3. Cargar usuario actual en contexto global
        current_user = None
        if user_id:
            current_user = Usuario.query.get(user_id)
            g.current_user = current_user
        else:
            g.current_user = None
            # Si no hay usuario, redirigir a login
            return redirect(url_for('main.login'))

        # 4. Verificar tiempo de inactividad
        config = Configuracion.obtener_config()
        timeout = config.tiempo_inactividad * 60  # Convertir a segundos

        last_activity = session.get('last_activity')
        current_time = time.time()

        if last_activity is None:
            # Primera actividad
            session['last_activity'] = current_time
        else:
            # Convertir a float si es necesario
            if isinstance(last_activity, str):
                try:
                    last_activity = float(last_activity)
                except (ValueError, TypeError):
                    last_activity = current_time

            # Calcular tiempo inactivo
            inactive_seconds = current_time - last_activity

            # Si supera el tiempo permitido
            if inactive_seconds > timeout:
                # Marcar sesión como expirada
                session['session_expired_flag'] = True
                return redirect(url_for('main.session_expired'))

        # 5. Actualizar actividad SOLO para rutas que no son de monitoreo
        if request.endpoint not in no_activity_update_routes:
            session['last_activity'] = current_time

        # 6. Manejo especial para formularios CSRF
        if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            # Verificar si es una solicitud de formulario
            content_type = request.headers.get('Content-Type', '')
            if 'application/x-www-form-urlencoded' in content_type or 'multipart/form-data' in content_type:
                # Validar token CSRF solo para formularios HTML
                from flask_wtf.csrf import validate_csrf
                try:
                    validate_csrf(request.form.get('csrf_token'))
                except:
                    current_app.logger.warning("Intento de formulario sin CSRF válido")
                    flash('Token CSRF inválido o faltante', 'danger')
                    return redirect(request.url)

    except Exception as e:
        current_app.logger.error(f"Error en middleware de sesión: {str(e)}")
        # Redirigir a login en caso de error crítico
        return redirect(url_for('main.login'))