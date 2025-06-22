# utils/decorators.py
from functools import wraps
from flask import redirect, flash, url_for, request, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from app.models import Usuario
from app.utils.logger import log_event


def role_required(roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                current_user = Usuario.query.get(user_id)

                if not current_user or current_user.rol not in roles:
                    flash('Acceso no autorizado', 'danger')
                    current_app.logger.warning(
                        f"Intento de acceso no autorizado a {request.path} por {current_user.usuario if current_user else 'anonimo'}")
                    return redirect(url_for('admin.admin_dashboard'))

                return fn(*args, **kwargs)
            except Exception as e:
                current_app.logger.error(f"Error en role_required: {str(e)}")
                flash('Error de autenticación', 'danger')
                return redirect(url_for('main.login'))

        return wrapper

    return decorator


def logged_route(roles=None, event_type=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            current_user = Usuario.query.get(user_id)

            # Registro de acceso
            log_event(
                user=current_user,
                event_type=event_type or f"access_{fn.__name__}",
                endpoint=request.endpoint,
                details=f"Acceso a {request.path}"
            )

            if roles and current_user.rol not in roles:
                log_event(
                    user=current_user,
                    event_type="unauthorized_access",
                    endpoint=request.endpoint,
                    details=f"Intento de acceso no autorizado a {request.path}"
                )
                return {"error": "Acceso no autorizado"}, 403

            return fn(*args, **kwargs)

        return wrapper

    return decorator