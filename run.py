from app import create_app, db

app = create_app()

@app.cli.command("create-admin")
def create_admin():
    """Crea un usuario administrador inicial"""
    from app.models import Usuario
    from app import bcrypt

    admin = Usuario(
        usuario="admin",
        password_hash=bcrypt.generate_password_hash("adminpasswordTulumxEver").decode('utf-8'),
        rol="admin"
    )

    with app.app_context():
        db.session.add(admin)
        db.session.commit()
    print("Usuario admin creado!")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=True)