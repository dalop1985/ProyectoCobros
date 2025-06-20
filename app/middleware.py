# app/middleware.py
from flask import request, g, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from app.models import Usuario


def session_handler():
    """Middleware para gestionar sesiones, autenticación y CSRF"""
    try:
        # 1. Eximir rutas públicas
        public_routes = ['main.login', 'static']
        if request.endpoint in public_routes:
            return

        # 2. Verificar JWT para rutas protegidas
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()

        # 3. Cargar usuario actual en contexto global
        if user_id:
            g.current_user = Usuario.query.get(user_id)
        else:
            g.current_user = None

        # 4. Manejo especial para formularios CSRF
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
                    return {'error': 'Token CSRF inválido o faltante'}, 403

    except Exception as e:
        current_app.logger.error(f"Error en middleware de sesión: {str(e)}")