from app import create_app
from app.models import Usuario

app = create_app()

with app.app_context():
    usuario = Usuario.query.filter_by(usuario="admin").first()
    print(usuario.id if usuario else "Usuario no encontrado",
          usuario.rol if usuario else "",
          usuario.password_hash if usuario else "")

with app.app_context():
    print(Usuario.query.count())  # Debería ser > 0
    print(Usuario.query.all())  # Lista todos los usuarios