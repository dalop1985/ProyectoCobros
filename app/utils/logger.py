# utils/logger.py
from flask import request, current_app
from user_agents import parse
from geoip2 import database
from geoip2.errors import AddressNotFoundError
from app import db

def log_event(user=None, event_type=None, endpoint=None, details=None):
    """Registra un evento en la bitácora de accesos"""
    try:
        # Obtener información de la solicitud
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.headers.get('User-Agent', '')

        # Parsear user agent para obtener información del dispositivo
        ua = parse(user_agent)
        device_info = f"{ua.device.family} {ua.device.model}" if ua.device.family else "Desktop"

        # Obtener ubicación aproximada
        location = get_location(ip_address)

        # Obtener el usuario actual (si está disponible)
        user_id = user.id if user else None

        from app.models import AccessLog

        # Convertir None a cadena vacía
        safe_details = details if details is not None else ''

        # Crear registro usando el contexto actual de la aplicación
        with current_app.app_context():
            log = AccessLog(
                user_id=user_id,
                ip_address=ip_address,
                event_type=event_type,
                endpoint=endpoint or request.endpoint,
                user_agent=user_agent,
                device_info=device_info,
                location=location,
                details=safe_details,
                request_method=request.method,
                request_path=request.path,
                request_data=str(request.form)[:500] if request.form else None
            )
            db.session.add(log)
            db.session.commit()



    except Exception as e:
        # Registrar error sin interrumpir el flujo
        current_app.logger.error(f"Error al registrar en bitácora: {e}")


def get_location(ip_address):
    """Obtiene la ubicación aproximada desde la IP"""
    try:
        # Intenta cargar la base de datos GeoLite2 si está disponible
        with database.Reader('utils/GeoLite2-City.mmdb') as reader:
            response = reader.city(ip_address)
            city = response.city.name or ""
            country = response.country.name or ""
            return f"{city}, {country}" if city and country else "Desconocido"
    except Exception:
        return "Error en geolocalización"