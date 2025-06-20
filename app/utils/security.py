# app/utils/security.py
import secrets
import string

def generar_contrasena_temporal(longitud=12):
    """Genera una contraseña temporal segura"""
    caracteres = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(caracteres) for _ in range(longitud))


def validar_fortaleza_contrasena(password):
    """Valida que la contraseña cumpla con políticas de seguridad"""
    if len(password) < 10:
        return False, "La contraseña debe tener al menos 10 caracteres"

    if not any(c.isupper() for c in password):
        return False, "Debe contener al menos una mayúscula"

    if not any(c.islower() for c in password):
        return False, "Debe contener al menos una minúscula"

    if not any(c.isdigit() for c in password):
        return False, "Debe contener al menos un número"

    if not any(c in string.punctuation for c in password):
        return False, "Debe contener al menos un carácter especial"

    return True, ""